//! Proof-oriented affine secp256k1 execution and exact operation tape.
//!
//! Affine formulas are deliberately used here: an inverse is supplied as a
//! witness and authenticated by one modular product, so a complete add costs
//! four product rows and a double costs five.  The tape retains every product,
//! linear operation, and point transition for later AIR materialization.

const std = @import("std");
const field = @import("secp256k1_field.zig");

const Secp256k1 = std.crypto.ecc.Secp256k1;

pub const Value = [field.limb_count]u8;
pub const wnaf_width: usize = 5;
pub const odd_table_size: usize = 1 << (wnaf_width - 2);
pub const maximum_wnaf_digits: usize = 257;
pub const endomorphism_lambda: u256 =
    37718080363155996902926221483475020450927657555482586988616620542887997980018;
pub const endomorphism_beta: u256 =
    55594575648329892869085402983802832744385952214688224221778511981742606582254;

pub const ModulusKind = enum(u1) {
    base,
    scalar,

    pub fn modulus(self: ModulusKind) field.Modulus {
        return switch (self) {
            .base => field.base_modulus,
            .scalar => field.scalar_modulus,
        };
    }
};

pub const LinearKind = enum {
    add,
    subtract,
    reduce_once,
};

pub const PointKind = enum {
    double,
    add,
    left_identity,
    right_identity,
    inverse_pair,
    double_identity,
    double_to_infinity,
};

pub const Point = struct {
    x: Value = @splat(0),
    y: Value = @splat(0),
    infinity: bool = true,

    pub fn eql(lhs: Point, rhs: Point) bool {
        if (lhs.infinity or rhs.infinity) return lhs.infinity == rhs.infinity;
        return std.mem.eql(u8, &lhs.x, &rhs.x) and std.mem.eql(u8, &lhs.y, &rhs.y);
    }
};

pub const ProductRecord = struct {
    modulus: ModulusKind,
    witness: field.Witness,
};

pub const LinearRecord = struct {
    kind: LinearKind,
    modulus: ModulusKind,
    lhs: Value,
    rhs: Value,
    result: Value,
};

pub const PointRecord = struct {
    kind: PointKind,
    lhs: Point,
    rhs: Point,
    result: Point,
    slope: Value = @splat(0),
    denominator_inverse: Value = @splat(0),
    product_start: u32,
    product_count: u8,
    linear_start: u32,
    linear_count: u8,
};

pub const ScalarSplitRecord = struct {
    original: Value,
    magnitude_1: Value,
    magnitude_2: Value,
    negative_1: bool,
    negative_2: bool,
    product_start: u32,
    product_count: u8,
    linear_start: u32,
    linear_count: u8,
};

pub const Tape = struct {
    allocator: std.mem.Allocator,
    products: std.ArrayList(ProductRecord) = .empty,
    linears: std.ArrayList(LinearRecord) = .empty,
    points: std.ArrayList(PointRecord) = .empty,
    scalar_splits: std.ArrayList(ScalarSplitRecord) = .empty,

    pub fn init(allocator: std.mem.Allocator) Tape {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Tape) void {
        self.products.deinit(self.allocator);
        self.linears.deinit(self.allocator);
        self.points.deinit(self.allocator);
        self.scalar_splits.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn mul(self: *Tape, kind: ModulusKind, lhs: Value, rhs: Value) !Value {
        const witness = try field.create(lhs, rhs, kind.modulus());
        try self.products.append(self.allocator, .{ .modulus = kind, .witness = witness });
        return witness.result;
    }

    pub fn add(self: *Tape, kind: ModulusKind, lhs: Value, rhs: Value) !Value {
        const modulus = kind.modulus().integer();
        const wide = @as(u512, integer(lhs)) + @as(u512, integer(rhs));
        const result = field.bytesFromInteger(@intCast(wide % @as(u512, modulus)));
        try self.linears.append(self.allocator, .{
            .kind = .add,
            .modulus = kind,
            .lhs = lhs,
            .rhs = rhs,
            .result = result,
        });
        return result;
    }

    pub fn sub(self: *Tape, kind: ModulusKind, lhs: Value, rhs: Value) !Value {
        const modulus = kind.modulus().integer();
        const lhs_int = integer(lhs);
        const rhs_int = integer(rhs);
        const result_int = if (lhs_int >= rhs_int)
            lhs_int - rhs_int
        else
            modulus - (rhs_int - lhs_int);
        const result = field.bytesFromInteger(result_int);
        try self.linears.append(self.allocator, .{
            .kind = .subtract,
            .modulus = kind,
            .lhs = lhs,
            .rhs = rhs,
            .result = result,
        });
        return result;
    }

    pub fn reduceScalarOnce(self: *Tape, value: Value) !Value {
        const value_int = integer(value);
        const modulus = field.scalar_modulus.integer();
        const result = field.bytesFromInteger(if (value_int >= modulus)
            value_int - modulus
        else
            value_int);
        try self.linears.append(self.allocator, .{
            .kind = .reduce_once,
            .modulus = .scalar,
            .lhs = value,
            .rhs = field.scalar_modulus.bytes,
            .result = result,
        });
        return result;
    }

    pub fn inverse(self: *Tape, kind: ModulusKind, value: Value) !Value {
        if (integer(value) == 0) return error.DivisionByZero;
        const inverse_value = switch (kind) {
            .base => blk: {
                const element = try Secp256k1.Fe.fromBytes(value, .little);
                break :blk element.invert().toBytes(.little);
            },
            .scalar => blk: {
                const element = try Secp256k1.scalar.Scalar.fromBytes(value, .little);
                break :blk element.invert().toBytes(.little);
            },
        };
        const product = try self.mul(kind, value, inverse_value);
        if (integer(product) != 1) return error.InvalidInverse;
        return inverse_value;
    }

    pub fn splitScalar(self: *Tape, value: Value) !SignedSplit {
        if (integer(value) >= field.scalar_modulus.integer())
            return error.NonCanonicalScalar;
        const product_start = self.products.items.len;
        const linear_start = self.linears.items.len;
        const raw = try Secp256k1.Endormorphism.splitScalar(value, .little);
        const first = try self.canonicalSplitMagnitude(raw.r1);
        const second = try self.canonicalSplitMagnitude(raw.r2);
        const lambda_product = try self.mul(
            .scalar,
            second.magnitude,
            field.bytesFromInteger(endomorphism_lambda),
        );
        const signed_first = if (first.negative)
            try self.sub(.scalar, @splat(0), first.magnitude)
        else
            first.magnitude;
        const signed_second_product = if (second.negative)
            try self.sub(.scalar, @splat(0), lambda_product)
        else
            lambda_product;
        const reconstructed = try self.add(.scalar, signed_first, signed_second_product);
        if (!std.mem.eql(u8, &reconstructed, &value))
            return error.InvalidScalarSplit;

        const product_count = self.products.items.len - product_start;
        const linear_count = self.linears.items.len - linear_start;
        if (product_start > std.math.maxInt(u32) or
            linear_start > std.math.maxInt(u32) or
            product_count > std.math.maxInt(u8) or
            linear_count > std.math.maxInt(u8))
        {
            return error.TapeOverflow;
        }
        try self.scalar_splits.append(self.allocator, .{
            .original = value,
            .magnitude_1 = first.magnitude,
            .magnitude_2 = second.magnitude,
            .negative_1 = first.negative,
            .negative_2 = second.negative,
            .product_start = @intCast(product_start),
            .product_count = @intCast(product_count),
            .linear_start = @intCast(linear_start),
            .linear_count = @intCast(linear_count),
        });
        return .{ .first = first, .second = second };
    }

    fn canonicalSplitMagnitude(self: *Tape, raw: Value) !SignedMagnitude {
        const zero: Value = @splat(0);
        const negative = raw[raw.len / 2] != 0;
        const magnitude = if (negative)
            try self.sub(.scalar, zero, raw)
        else
            raw;
        for (magnitude[magnitude.len / 2 ..]) |byte| {
            if (byte != 0) return error.InvalidScalarSplit;
        }
        return .{ .magnitude = magnitude, .negative = negative };
    }
};

pub const SignedMagnitude = struct {
    magnitude: Value,
    negative: bool,
};

pub const SignedSplit = struct {
    first: SignedMagnitude,
    second: SignedMagnitude,
};

pub fn basePoint() Point {
    return pointFromStd(Secp256k1.basePoint);
}

pub fn pointFromSec1(encoded: []const u8) !Point {
    return pointFromStd(try Secp256k1.fromSec1(encoded));
}

pub fn pointToStd(point: Point) !Secp256k1 {
    if (point.infinity) return Secp256k1.identityElement;
    return Secp256k1.fromSerializedAffineCoordinates(point.x, point.y, .little);
}

pub fn double(tape: *Tape, point: Point) !Point {
    const product_start = tape.products.items.len;
    const linear_start = tape.linears.items.len;
    if (point.infinity) {
        try appendPoint(tape, .double_identity, point, .{}, point, @splat(0), @splat(0), product_start, linear_start);
        return point;
    }
    if (integer(point.y) == 0) {
        const result = Point{};
        try appendPoint(tape, .double_to_infinity, point, .{}, result, @splat(0), @splat(0), product_start, linear_start);
        return result;
    }

    const xx = try tape.mul(.base, point.x, point.x);
    const two_xx = try tape.add(.base, xx, xx);
    const numerator = try tape.add(.base, two_xx, xx);
    const denominator = try tape.add(.base, point.y, point.y);
    const denominator_inverse = try tape.inverse(.base, denominator);
    const slope = try tape.mul(.base, numerator, denominator_inverse);
    const slope_squared = try tape.mul(.base, slope, slope);
    const x_after_one = try tape.sub(.base, slope_squared, point.x);
    const x_out = try tape.sub(.base, x_after_one, point.x);
    const x_delta = try tape.sub(.base, point.x, x_out);
    const y_product = try tape.mul(.base, slope, x_delta);
    const y_out = try tape.sub(.base, y_product, point.y);
    const result = Point{ .x = x_out, .y = y_out, .infinity = false };
    try appendPoint(
        tape,
        .double,
        point,
        .{},
        result,
        slope,
        denominator_inverse,
        product_start,
        linear_start,
    );
    return result;
}

pub fn addPoints(tape: *Tape, lhs: Point, rhs: Point) !Point {
    const product_start = tape.products.items.len;
    const linear_start = tape.linears.items.len;
    if (lhs.infinity) {
        try appendPoint(tape, .left_identity, lhs, rhs, rhs, @splat(0), @splat(0), product_start, linear_start);
        return rhs;
    }
    if (rhs.infinity) {
        try appendPoint(tape, .right_identity, lhs, rhs, lhs, @splat(0), @splat(0), product_start, linear_start);
        return lhs;
    }
    if (std.mem.eql(u8, &lhs.x, &rhs.x)) {
        if (std.mem.eql(u8, &lhs.y, &rhs.y)) return double(tape, lhs);
        const y_sum = try tape.add(.base, lhs.y, rhs.y);
        if (integer(y_sum) != 0) return error.InvalidPointPair;
        const result = Point{};
        try appendPoint(tape, .inverse_pair, lhs, rhs, result, @splat(0), @splat(0), product_start, linear_start);
        return result;
    }

    const denominator = try tape.sub(.base, rhs.x, lhs.x);
    const numerator = try tape.sub(.base, rhs.y, lhs.y);
    const denominator_inverse = try tape.inverse(.base, denominator);
    const slope = try tape.mul(.base, numerator, denominator_inverse);
    const slope_squared = try tape.mul(.base, slope, slope);
    const x_after_lhs = try tape.sub(.base, slope_squared, lhs.x);
    const x_out = try tape.sub(.base, x_after_lhs, rhs.x);
    const x_delta = try tape.sub(.base, lhs.x, x_out);
    const y_product = try tape.mul(.base, slope, x_delta);
    const y_out = try tape.sub(.base, y_product, lhs.y);
    const result = Point{ .x = x_out, .y = y_out, .infinity = false };
    try appendPoint(
        tape,
        .add,
        lhs,
        rhs,
        result,
        slope,
        denominator_inverse,
        product_start,
        linear_start,
    );
    return result;
}

pub fn doubleScalarWnaf(
    tape: *Tape,
    generator_scalar: Value,
    point: Point,
    point_scalar: Value,
) !Point {
    if (integer(generator_scalar) >= field.scalar_modulus.integer() or
        integer(point_scalar) >= field.scalar_modulus.integer())
    {
        return error.NonCanonicalScalar;
    }
    if (point.infinity) return error.IdentityPoint;

    const generator_digits = wnaf(generator_scalar);
    const point_digits = wnaf(point_scalar);
    const generator_table = fixedGeneratorOddTable();
    const point_table = try oddTable(tape, point);
    const highest = @max(generator_digits.length, point_digits.length);

    var accumulator = Point{};
    var index = highest;
    while (index != 0) {
        index -= 1;
        accumulator = try double(tape, accumulator);
        if (generator_digits.digits[index] != 0) {
            const selected = try signedSelection(
                tape,
                &generator_table,
                generator_digits.digits[index],
                false,
            );
            accumulator = try addPoints(tape, accumulator, selected);
        }
        if (point_digits.digits[index] != 0) {
            const selected = try signedSelection(
                tape,
                &point_table,
                point_digits.digits[index],
                true,
            );
            accumulator = try addPoints(tape, accumulator, selected);
        }
    }
    return accumulator;
}

/// GLV-accelerated joint multiplication.  Both scalar decompositions and the
/// variable-point endomorphism are retained in the operation tape.
pub fn doubleScalarGlvWnaf(
    tape: *Tape,
    generator_scalar: Value,
    point: Point,
    point_scalar: Value,
) !Point {
    if (point.infinity) return error.IdentityPoint;
    const generator_split = try tape.splitScalar(generator_scalar);
    const point_split = try tape.splitScalar(point_scalar);
    const point_endomorphism = try endomorphismPoint(tape, point);

    const generator_table = fixedGeneratorOddTable();
    const generator_endomorphism_table = fixedGeneratorEndomorphismOddTable();
    const point_table = try oddTable(tape, point);
    const point_endomorphism_table = try oddTable(tape, point_endomorphism);

    const generator_first = wnaf(generator_split.first.magnitude);
    const generator_second = wnaf(generator_split.second.magnitude);
    const point_first = wnaf(point_split.first.magnitude);
    const point_second = wnaf(point_split.second.magnitude);
    const highest = @max(
        @max(generator_first.length, generator_second.length),
        @max(point_first.length, point_second.length),
    );
    if (highest > 130) return error.InvalidScalarSplit;

    var accumulator = Point{};
    var index = highest;
    while (index != 0) {
        index -= 1;
        accumulator = try double(tape, accumulator);
        accumulator = try addDigit(
            tape,
            accumulator,
            &generator_table,
            signedDigit(generator_first.digits[index], generator_split.first.negative),
            false,
        );
        accumulator = try addDigit(
            tape,
            accumulator,
            &generator_endomorphism_table,
            signedDigit(generator_second.digits[index], generator_split.second.negative),
            false,
        );
        accumulator = try addDigit(
            tape,
            accumulator,
            &point_table,
            signedDigit(point_first.digits[index], point_split.first.negative),
            true,
        );
        accumulator = try addDigit(
            tape,
            accumulator,
            &point_endomorphism_table,
            signedDigit(point_second.digits[index], point_split.second.negative),
            true,
        );
    }
    return accumulator;
}

pub fn verifyEcdsa(
    tape: *Tape,
    digest_big_endian: [32]u8,
    public_key_sec1: [65]u8,
    r_big_endian: [32]u8,
    s_big_endian: [32]u8,
) !bool {
    const public_key = pointFromSec1(&public_key_sec1) catch return false;
    var digest = reverse(digest_big_endian);
    const r = reverse(r_big_endian);
    const s = reverse(s_big_endian);
    const order = field.scalar_modulus.integer();
    if (integer(r) == 0 or integer(s) == 0 or integer(r) >= order or integer(s) >= order)
        return false;

    digest = try tape.reduceScalarOnce(digest);
    const inverse_s = try tape.inverse(.scalar, s);
    const generator_scalar = try tape.mul(.scalar, digest, inverse_s);
    const public_key_scalar = try tape.mul(.scalar, r, inverse_s);
    const result = try doubleScalarGlvWnaf(
        tape,
        generator_scalar,
        public_key,
        public_key_scalar,
    );
    if (result.infinity) return false;
    const x_scalar = try tape.reduceScalarOnce(result.x);
    return std.mem.eql(u8, &x_scalar, &r);
}

const Wnaf = struct {
    digits: [maximum_wnaf_digits]i8 = @splat(0),
    length: usize = 0,
};

fn wnaf(value: Value) Wnaf {
    var result = Wnaf{};
    var scalar: i512 = @intCast(integer(value));
    while (scalar != 0) : (result.length += 1) {
        std.debug.assert(result.length < maximum_wnaf_digits);
        if (@mod(scalar, 2) != 0) {
            var digit: i16 = @intCast(@mod(scalar, 1 << wnaf_width));
            if (digit >= 1 << (wnaf_width - 1)) digit -= 1 << wnaf_width;
            result.digits[result.length] = @intCast(digit);
            scalar -= digit;
        }
        scalar = @divExact(scalar, 2);
    }
    return result;
}

fn oddTable(tape: *Tape, point: Point) ![odd_table_size]Point {
    var result: [odd_table_size]Point = undefined;
    result[0] = point;
    const twice = try double(tape, point);
    for (1..odd_table_size) |index| result[index] =
        try addPoints(tape, result[index - 1], twice);
    return result;
}

fn fixedGeneratorOddTable() [odd_table_size]Point {
    return fixedOddTable(basePoint());
}

fn fixedGeneratorEndomorphismOddTable() [odd_table_size]Point {
    const generator = basePoint();
    const beta = field.bytesFromInteger(endomorphism_beta);
    const x = field.create(generator.x, beta, field.base_modulus) catch unreachable;
    return fixedOddTable(.{ .x = x.result, .y = generator.y, .infinity = false });
}

fn fixedOddTable(point: Point) [odd_table_size]Point {
    var result: [odd_table_size]Point = undefined;
    var current = pointToStd(point) catch unreachable;
    const twice = current.dbl();
    for (&result) |*entry| {
        entry.* = pointFromStd(current);
        current = current.add(twice);
    }
    return result;
}

fn endomorphismPoint(tape: *Tape, point: Point) !Point {
    if (point.infinity) return point;
    return .{
        .x = try tape.mul(
            .base,
            point.x,
            field.bytesFromInteger(endomorphism_beta),
        ),
        .y = point.y,
        .infinity = false,
    };
}

fn addDigit(
    tape: *Tape,
    accumulator: Point,
    table: *const [odd_table_size]Point,
    digit: i8,
    record_negation: bool,
) !Point {
    if (digit == 0) return accumulator;
    return addPoints(
        tape,
        accumulator,
        try signedSelection(tape, table, digit, record_negation),
    );
}

fn signedDigit(digit: i8, negative: bool) i8 {
    return if (negative) -digit else digit;
}

fn signedSelection(
    tape: *Tape,
    table: *const [odd_table_size]Point,
    digit: i8,
    record_negation: bool,
) !Point {
    std.debug.assert(digit != 0 and @mod(digit, 2) != 0);
    const magnitude: u8 = @intCast(if (digit < 0) -@as(i16, digit) else digit);
    var result = table[(magnitude - 1) / 2];
    if (digit < 0) {
        if (record_negation) {
            result.y = try tape.sub(.base, @splat(0), result.y);
        } else {
            const p = field.base_modulus.integer();
            result.y = field.bytesFromInteger(if (integer(result.y) == 0)
                0
            else
                p - integer(result.y));
        }
    }
    return result;
}

fn appendPoint(
    tape: *Tape,
    kind: PointKind,
    lhs: Point,
    rhs: Point,
    result: Point,
    slope: Value,
    denominator_inverse: Value,
    product_start: usize,
    linear_start: usize,
) !void {
    const product_count = tape.products.items.len - product_start;
    const linear_count = tape.linears.items.len - linear_start;
    if (product_start > std.math.maxInt(u32) or linear_start > std.math.maxInt(u32) or
        product_count > std.math.maxInt(u8) or linear_count > std.math.maxInt(u8))
    {
        return error.TapeOverflow;
    }
    try tape.points.append(tape.allocator, .{
        .kind = kind,
        .lhs = lhs,
        .rhs = rhs,
        .result = result,
        .slope = slope,
        .denominator_inverse = denominator_inverse,
        .product_start = @intCast(product_start),
        .product_count = @intCast(product_count),
        .linear_start = @intCast(linear_start),
        .linear_count = @intCast(linear_count),
    });
}

fn pointFromStd(point: Secp256k1) Point {
    if (point.equivalent(Secp256k1.identityElement)) return .{};
    const encoded = point.toUncompressedSec1();
    return .{
        .x = reverse(encoded[1..33].*),
        .y = reverse(encoded[33..65].*),
        .infinity = false,
    };
}

fn reverse(input: [32]u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (input, 0..) |byte, index| result[input.len - 1 - index] = byte;
    return result;
}

fn integer(value: Value) u256 {
    return std.mem.readInt(u256, &value, .little);
}
