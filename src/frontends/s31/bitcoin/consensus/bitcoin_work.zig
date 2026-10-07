//! Checked unsigned 256-bit division and Bitcoin block work.
//!
//! Multiplication uses base-256 digits. At every column, 32 byte products,
//! one remainder byte, and a 16-bit carry total at most 2,146,590 < M31.
//! Therefore each M31 column equality is also an integer equality. The
//! terminal zero carry forbids truncation of the 512-bit product.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Var = circuit.builder.Var;

pub const Words = [16]Var;
pub const Target = struct { words: Words };
pub const Work = struct { words: Words };
pub const ChainWork = struct { words: Words };
pub const Division = struct { quotient: Words, remainder: Words };
pub const Witness = struct { quotient: u256, remainder: u256 };

fn hint(comptime V: type, value: u32) V {
    return circuit.builder.ivalue.fromQm31(V, QM31.fromBase(M31.fromCanonical(value)));
}

fn valueOf(comptime V: type, ctx: *circuit.builder.Context(V), wire: Var) u32 {
    return if (comptime V == QM31) ctx.get(wire).toM31Array()[0].v else 0;
}

fn value256(comptime V: type, ctx: *circuit.builder.Context(V), words: Words) u256 {
    var value: u256 = 0;
    for (words, 0..) |word, i|
        value |= @as(u256, valueOf(V, ctx, word) & 0xffff) << @as(u8, @intCast(16 * i));
    return value;
}

fn bit(comptime V: type, ctx: *circuit.builder.Context(V), value: u32) !Var {
    const wire = try ctx.guessM31(hint(V, value));
    try ctx.eq(try ctx.mul(wire, try ctx.sub(wire, ctx.one())), ctx.zero());
    return wire;
}

fn byte(comptime V: type, ctx: *circuit.builder.Context(V), value: u32) !Var {
    var word = ctx.zero();
    for (0..8) |i| {
        const component = try bit(V, ctx, (value >> @as(u5, @intCast(i))) & 1);
        const weight = try ctx.constant(QM31.fromBase(M31.fromCanonical(@as(u32, 1) << @as(u5, @intCast(i)))));
        word = try ctx.add(word, try ctx.mul(component, weight));
    }
    return word;
}

fn splitWords(comptime V: type, ctx: *circuit.builder.Context(V), words: Words) ![32]Var {
    const base = try ctx.constant(QM31.fromBase(M31.fromCanonical(256)));
    var result: [32]Var = undefined;
    for (words, 0..) |word, i| {
        const value = valueOf(V, ctx, word);
        result[2 * i] = try byte(V, ctx, value & 0xff);
        result[2 * i + 1] = try byte(V, ctx, (value >> 8) & 0xff);
        try ctx.eq(word, try ctx.add(result[2 * i], try ctx.mul(result[2 * i + 1], base)));
    }
    return result;
}

fn witnessBytes(comptime V: type, ctx: *circuit.builder.Context(V), value: u256) !witnessBytesResult {
    const base = try ctx.constant(QM31.fromBase(M31.fromCanonical(256)));
    var result: witnessBytesResult = undefined;
    for (0..16) |i| {
        const low: u32 = @intCast((value >> @as(u8, @intCast(16 * i))) & 0xff);
        const high: u32 = @intCast((value >> @as(u8, @intCast(16 * i + 8))) & 0xff);
        result.bytes[2 * i] = try byte(V, ctx, low);
        result.bytes[2 * i + 1] = try byte(V, ctx, high);
        result.words[i] = try ctx.add(result.bytes[2 * i], try ctx.mul(result.bytes[2 * i + 1], base));
    }
    return result;
}

const witnessBytesResult = struct { bytes: [32]Var, words: Words };

/// This API accepts `Words` whose canonical range is proved inside the
/// operation. A caller cannot bypass the quotient, remainder, or divisor
/// checks by supplying field elements outside the u16 range.
pub fn divRemU256(comptime V: type, ctx: *circuit.builder.Context(V), numerator: Words, denominator: Words) !Division {
    const n = value256(V, ctx, numerator);
    const d = value256(V, ctx, denominator);
    if (comptime V == QM31) {
        if (d == 0) return error.ZeroDivisor;
    }
    return divRemU256WithWitness(V, ctx, numerator, denominator, .{
        .quotient = if (d == 0) 0 else n / d,
        .remainder = if (d == 0) 0 else n % d,
    });
}

/// The explicit witness entry point is useful for adversarial tests. Its
/// equations, rather than the witness generator, determine validity.
pub fn divRemU256WithWitness(comptime V: type, ctx: *circuit.builder.Context(V), numerator: Words, denominator: Words, witness: Witness) !Division {
    const n = try splitWords(V, ctx, numerator);
    const d = try splitWords(V, ctx, denominator);
    const q = try witnessBytes(V, ctx, witness.quotient);
    const r = try witnessBytes(V, ctx, witness.remainder);
    const base = try ctx.constant(QM31.fromBase(M31.fromCanonical(256)));

    // q*d+r=n over the integers, including zero high product columns.
    var incoming = ctx.zero();
    var carry_value: u32 = 0;
    for (0..64) |column| {
        var sum = incoming;
        var integer_sum: u32 = carry_value;
        const first = if (column < 32) 0 else column - 31;
        const end = @min(column + 1, 32);
        for (first..end) |i| {
            sum = try ctx.add(sum, try ctx.mul(q.bytes[i], d[column - i]));
            const qi: u32 = @intCast((witness.quotient >> @as(u8, @intCast(8 * i))) & 0xff);
            const di = valueOf(V, ctx, denominator[(column - i) / 2]);
            const db = if ((column - i) % 2 == 0) di & 0xff else (di >> 8) & 0xff;
            integer_sum += qi * db;
        }
        if (column < 32) {
            sum = try ctx.add(sum, r.bytes[column]);
            integer_sum += @intCast((witness.remainder >> @as(u8, @intCast(8 * column))) & 0xff);
        }
        const digit = if (column < 32) n[column] else ctx.zero();
        const digit_value: u32 = if (column < 32) blk: {
            const limb = valueOf(V, ctx, numerator[column / 2]);
            break :blk if (column % 2 == 0) limb & 0xff else (limb >> 8) & 0xff;
        } else 0;
        const next_value = if (integer_sum >= digit_value and (integer_sum - digit_value) % 256 == 0)
            (integer_sum - digit_value) / 256
        else
            integer_sum / 256;
        const outgoing = try ctx.guessU16(hint(V, next_value));
        try ctx.eq(sum, try ctx.add(digit, try ctx.mul(outgoing, base)));
        incoming = outgoing;
        carry_value = next_value;
    }
    try ctx.eq(incoming, ctx.zero());

    // Strict r<d follows from d-r-1 >= 0. Each 16-bit subtraction equation
    // is below 2^18, so it cannot hide a field wrap.
    const limb_base = try ctx.constant(QM31.fromBase(M31.fromCanonical(65536)));
    var borrow = ctx.one();
    var borrow_value: u32 = 1;
    for (0..16) |i| {
        const rv: u32 = @intCast((witness.remainder >> @as(u8, @intCast(16 * i))) & 0xffff);
        const dv = valueOf(V, ctx, denominator[i]);
        const next_value: u32 = @intFromBool(dv < rv + borrow_value);
        const diff_value = (dv + 65536 - rv - borrow_value) & 0xffff;
        const next = try bit(V, ctx, next_value);
        const diff = try ctx.guessU16(hint(V, diff_value));
        try ctx.eq(try ctx.add(denominator[i], try ctx.mul(next, limb_base)), try ctx.add(try ctx.add(r.words[i], borrow), diff));
        borrow = next;
        borrow_value = next_value;
    }
    try ctx.eq(borrow, ctx.zero());
    return .{ .quotient = q.words, .remainder = r.words };
}

/// Add one without allowing 256-bit overflow.
fn addOneChecked(comptime V: type, ctx: *circuit.builder.Context(V), input: Words) !Words {
    const base = try ctx.constant(QM31.fromBase(M31.fromCanonical(65536)));
    var carry = ctx.one();
    var carry_value: u32 = 1;
    var result: Words = undefined;
    for (input, &result) |word, *output| {
        const value = valueOf(V, ctx, word) + carry_value;
        output.* = try ctx.guessU16(hint(V, value & 0xffff));
        const next_value = value >> 16;
        const next = try bit(V, ctx, next_value);
        try ctx.eq(try ctx.add(word, carry), try ctx.add(output.*, try ctx.mul(next, base)));
        carry = next;
        carry_value = next_value;
    }
    try ctx.eq(carry, ctx.zero());
    return result;
}

/// Bitcoin Core's floor(2^256/(target+1)) for a nonzero 256-bit target.
/// The final checked +1 rejects zero target; t+1 rejects 2^256-1.
pub fn blockWork(comptime V: type, ctx: *circuit.builder.Context(V), target: Words) !Words {
    const max_digit = try ctx.constant(QM31.fromBase(M31.fromCanonical(65535)));
    var complement: Words = undefined;
    for (target, &complement) |digit, *result| result.* = try ctx.sub(max_digit, digit);
    const denominator = try addOneChecked(V, ctx, target);
    const division = try divRemU256(V, ctx, complement, denominator);
    return addOneChecked(V, ctx, division.quotient);
}

pub fn workForTarget(comptime V: type, ctx: *circuit.builder.Context(V), target: Target) !Work {
    return .{ .words = try blockWork(V, ctx, target.words) };
}

/// Checked chainwork accumulation. The nominal wrapper prevents a target
/// from being used as accumulated work by mistake at the Zig API boundary.
pub fn addChainWorkChecked(comptime V: type, ctx: *circuit.builder.Context(V), total: ChainWork, delta: Work) !ChainWork {
    const base = try ctx.constant(QM31.fromBase(M31.fromCanonical(65536)));
    var output: Words = undefined;
    var carry = ctx.zero();
    var carry_value: u32 = 0;
    for (total.words, delta.words, &output) |left, right, *digit| {
        const left_value = valueOf(V, ctx, left);
        const right_value = valueOf(V, ctx, right);
        const checked_left = try ctx.guessU16(hint(V, left_value & 0xffff));
        const checked_right = try ctx.guessU16(hint(V, right_value & 0xffff));
        try ctx.eq(left, checked_left);
        try ctx.eq(right, checked_right);
        const sum = (left_value & 0xffff) + (right_value & 0xffff) + carry_value;
        digit.* = try ctx.guessU16(hint(V, sum & 0xffff));
        const next_value = sum >> 16;
        const next = try bit(V, ctx, next_value);
        try ctx.eq(try ctx.add(try ctx.add(checked_left, checked_right), carry), try ctx.add(digit.*, try ctx.mul(next, base)));
        carry = next;
        carry_value = next_value;
    }
    try ctx.eq(carry, ctx.zero());
    return .{ .words = output };
}

test "checked division matches integer arithmetic and rejects false witnesses" {
    const cases = [_]struct { n: u256, d: u256 }{
        .{ .n = 0, .d = 1 },
        .{ .n = 1, .d = 2 },
        .{ .n = std.math.maxInt(u256), .d = 1 },
        .{ .n = std.math.maxInt(u256), .d = @as(u256, 0xffff) << 208 },
        .{ .n = 0x123456789abcdef0fedcba9876543210, .d = 0x10000000000000001 },
    };
    for (cases) |case| {
        var ctx = try circuit.builder.Context(QM31).init(std.testing.allocator, 1);
        defer ctx.deinit();
        const n = try inputWords(&ctx, case.n);
        const d = try inputWords(&ctx, case.d);
        const result = try divRemU256(QM31, &ctx, n, d);
        try std.testing.expectEqual(case.n / case.d, value256(QM31, &ctx, result.quotient));
        try std.testing.expectEqual(case.n % case.d, value256(QM31, &ctx, result.remainder));
        try ctx.setOutputs(&.{result.quotient[0]});
        try ctx.finalize(false);
        try std.testing.expect(ctx.gate_counts.qm31_ops <= 7600);
        try std.testing.expect(ctx.gate_counts.eq <= 1200);
        try std.testing.expect(try ctx.isCircuitValid());
    }
    const bad = [_]Witness{
        .{ .quotient = 4, .remainder = 0 }, // true quotient 3, remainder 2
        .{ .quotient = 3, .remainder = 2 + 65536 },
        .{ .quotient = 2, .remainder = 7 }, // integer equality, but r>=d
    };
    for (bad) |witness| {
        var ctx = try circuit.builder.Context(QM31).init(std.testing.allocator, 1);
        defer ctx.deinit();
        const n = try inputWords(&ctx, 17);
        const d = try inputWords(&ctx, 5);
        const result = try divRemU256WithWitness(QM31, &ctx, n, d, witness);
        try ctx.setOutputs(&.{result.quotient[0]});
        try ctx.finalize(false);
        try std.testing.expect(!(try ctx.isCircuitValid()));
    }
    // The high half of q*d cannot be silently discarded.
    {
        var ctx = try circuit.builder.Context(QM31).init(std.testing.allocator, 1);
        defer ctx.deinit();
        const max = std.math.maxInt(u256);
        const n = try inputWords(&ctx, max);
        const d = try inputWords(&ctx, max);
        const result = try divRemU256WithWitness(QM31, &ctx, n, d, .{ .quotient = 2, .remainder = 1 });
        try ctx.setOutputs(&.{result.quotient[0]});
        try ctx.finalize(false);
        try std.testing.expect(!(try ctx.isCircuitValid()));
    }
    // No quotient/remainder can satisfy the strict r<d relation for d=0.
    {
        var ctx = try circuit.builder.Context(QM31).init(std.testing.allocator, 1);
        defer ctx.deinit();
        const n = try inputWords(&ctx, 0);
        const d = try inputWords(&ctx, 0);
        try std.testing.expectError(error.ZeroDivisor, divRemU256(QM31, &ctx, n, d));
        const result = try divRemU256WithWitness(QM31, &ctx, n, d, .{ .quotient = 0, .remainder = 0 });
        try ctx.setOutputs(&.{result.quotient[0]});
        try ctx.finalize(false);
        try std.testing.expect(!(try ctx.isCircuitValid()));
    }
    // A caller passing a field element outside the u16 range cannot exploit
    // the witness generator's low-16-bit interpretation of the input.
    {
        var ctx = try circuit.builder.Context(QM31).init(std.testing.allocator, 1);
        defer ctx.deinit();
        var n = try inputWords(&ctx, 0);
        n[0] = try ctx.guessM31(hint(QM31, 70000));
        const d = try inputWords(&ctx, 1);
        const result = try divRemU256WithWitness(QM31, &ctx, n, d, .{ .quotient = 4464, .remainder = 0 });
        try ctx.setOutputs(&.{result.quotient[0]});
        try ctx.finalize(false);
        try std.testing.expect(!(try ctx.isCircuitValid()));
    }
}

test "block work matches 512-bit reference and rejects boundary targets" {
    for ([_]u256{ 1, 2, @as(u256, 0xffff) << 208, (@as(u256, 1) << 224) - 1 }) |target| {
        var ctx = try circuit.builder.Context(QM31).init(std.testing.allocator, 1);
        defer ctx.deinit();
        const words = try inputWords(&ctx, target);
        const output = try blockWork(QM31, &ctx, words);
        const expected: u256 = @intCast((@as(u512, 1) << 256) / (@as(u512, target) + 1));
        try std.testing.expectEqual(expected, value256(QM31, &ctx, output));
        try ctx.setOutputs(&.{output[0]});
        try ctx.finalize(false);
        try std.testing.expect(ctx.gate_counts.qm31_ops <= 7800);
        try std.testing.expect(ctx.gate_counts.eq <= 1250);
        try std.testing.expect(try ctx.isCircuitValid());
    }
    {
        var ctx = try circuit.builder.Context(QM31).init(std.testing.allocator, 1);
        defer ctx.deinit();
        const zero = try inputWords(&ctx, 0);
        const output = try blockWork(QM31, &ctx, zero);
        try ctx.setOutputs(&.{output[0]});
        try ctx.finalize(false);
        try std.testing.expect(!(try ctx.isCircuitValid()));
    }
    {
        var ctx = try circuit.builder.Context(QM31).init(std.testing.allocator, 1);
        defer ctx.deinit();
        const max = try inputWords(&ctx, std.math.maxInt(u256));
        try std.testing.expectError(error.ZeroDivisor, blockWork(QM31, &ctx, max));
    }
}

test "nominal chainwork addition is checked" {
    {
        var ctx = try circuit.builder.Context(QM31).init(std.testing.allocator, 1);
        defer ctx.deinit();
        const total: ChainWork = .{ .words = try inputWords(&ctx, 0x123456789abcdef0) };
        const delta: Work = .{ .words = try inputWords(&ctx, 0x10000000000000001) };
        const output = try addChainWorkChecked(QM31, &ctx, total, delta);
        try std.testing.expectEqual(@as(u256, 0x1123456789abcdef1), value256(QM31, &ctx, output.words));
        try ctx.setOutputs(&.{output.words[0]});
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
    }
    {
        var ctx = try circuit.builder.Context(QM31).init(std.testing.allocator, 1);
        defer ctx.deinit();
        const total: ChainWork = .{ .words = try inputWords(&ctx, std.math.maxInt(u256)) };
        const delta: Work = .{ .words = try inputWords(&ctx, 1) };
        const output = try addChainWorkChecked(QM31, &ctx, total, delta);
        try ctx.setOutputs(&.{output.words[0]});
        try ctx.finalize(false);
        try std.testing.expect(!(try ctx.isCircuitValid()));
    }
}

fn inputWords(ctx: *circuit.builder.Context(QM31), value: u256) !Words {
    var result: Words = undefined;
    for (&result, 0..) |*word, i|
        word.* = try ctx.guessU16(hint(QM31, @intCast((value >> @as(u8, @intCast(16 * i))) & 0xffff)));
    return result;
}
