//! Sixteen semantic Word16 shifts per physical input row. Stage one seals all
//! sixteen multiplicities. Eight strict product inverses share one cyclic sum.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const Word = @import("shift_word_table.zig");
const Range = @import("../providers/scalar_range.zig");
const Pair = @import("shift_lookup_pair.zig");
const Bus = @import("function_bus.zig");
const physical = @import("../witness.zig").physical;
const M = core.fields.m31.M31;
const Q = E.Q;
pub const LOG: u32 = 16;
pub const SIZE: usize = 1 << LOG;
pub const SEMANTIC_FACTS = Word.SIZE;
pub const FIXED = 18;
pub const MAIN = 16;
pub const INTERACTION = 36;
pub const CONSTRAINTS = 10;
pub const SHAPE_TAG: u32 = 0x53575031;
pub const SEMANTIC_TAG = Word.DOMAIN_TAG;
pub const Challenges = Word.Challenges;

pub fn tupleFor(comptime F: type, fixed: []const F, amount: usize) [6]F {
    std.debug.assert(fixed.len >= FIXED and amount < 16);
    const x = fixed[0];
    if (amount == 0) return .{ x, F.zero(), x, F.zero(), x, F.zero() };
    const low = fixed[amount];
    const carry = fixed[16 - amount];
    const power: u32 = @as(u32, 1) << @as(u5, @intCast(amount));
    const complement: u32 = @as(u32, 1) << @as(u5, @intCast(16 - amount));
    return .{ x, E.qFor(F, @intCast(amount)), x.mul(E.qFor(F, power)).sub(carry.mul(E.qFor(F, 65536))), carry, low, x.sub(low.mul(E.qFor(F, power))).mul(E.qFor(F, complement)) };
}

/// Algebraically the same six-coordinate affine denominator, prepared once
/// per challenge. This also holds for arbitrary non-base OODS coordinates.
pub const Prepared = struct {
    offsets: [16]Q,
    x_coefficients: [16]Q,
    left: Q,
    right: Q,
    pub fn init(ch: Challenges) Prepared {
        const c = ch.coefficients;
        var result = Prepared{ .offsets = undefined, .x_coefficients = undefined, .left = c[3].sub(c[2].mulM31(M.fromCanonical(65536))), .right = c[4].sub(c[5].mulM31(M.fromCanonical(65536))) };
        result.offsets[0] = ch.offset;
        result.x_coefficients[0] = c[0].add(c[2]).add(c[4]);
        for (1..16) |r| {
            const power = M.fromCanonical(@as(u32, 1) << @as(u5, @intCast(r)));
            const complement = M.fromCanonical(@as(u32, 1) << @as(u5, @intCast(16 - r)));
            result.offsets[r] = ch.offset.sub(c[1].mulM31(M.fromCanonical(@intCast(r))));
            result.x_coefficients[r] = c[0].add(c[2].mulM31(power)).add(c[5].mulM31(complement));
        }
        return result;
    }
    pub fn denominatorFor(self: *const Prepared, comptime F: type, fixed: []const F, r: usize) E.SecureFor(F) {
        var d = E.splatFor(F, self.offsets[r]).sub(E.mulBaseFor(F, E.splatFor(F, self.x_coefficients[r]), fixed[0]));
        if (r != 0) {
            d = d.sub(E.mulBaseFor(F, E.splatFor(F, self.left), fixed[16 - r]));
            d = d.sub(E.mulBaseFor(F, E.splatFor(F, self.right), fixed[r]));
        }
        return d;
    }
};

pub fn emitFor(comptime F: type, fixed: []const F, main: []const F, current: []const F, previous: []const F, claim: Q, prepared: *const Prepared, sink: *E.SinkFor(F)) void {
    var contribution = E.SecureFor(F).zero();
    for (0..8) |pair| {
        const a = prepared.denominatorFor(F, fixed, 2 * pair);
        const b = prepared.denominatorFor(F, fixed, 2 * pair + 1);
        const term = Pair.weightedForDenominators(F, a, b, E.secureFor(F, current, 4 * pair), main[2 * pair].neg(), main[2 * pair + 1].neg());
        sink.emit(term.residual);
        contribution = contribution.add(term.contribution);
    }
    Range.prefix(F, contribution, E.secureFor(F, current, 32), E.secureFor(F, previous, 32), fixed[16], fixed[17], claim, sink);
}

pub const Setup = struct {
    allocator: std.mem.Allocator,
    fixed: []M,
    pub fn init(a: std.mem.Allocator) !Setup {
        const fixed = try a.alloc(M, FIXED * SIZE);
        @memset(fixed, M.zero());
        for (0..SIZE) |x| {
            const row = physical(x, LOG);
            fixed[row] = M.fromCanonical(@intCast(x));
            for (1..16) |r| fixed[r * SIZE + row] = M.fromCanonical(Word.tupleAt(16 * x + r)[4]);
        }
        fixed[16 * SIZE + physical(0, LOG)] = M.one();
        fixed[17 * SIZE + physical(SIZE - 1, LOG)] = M.one();
        return .{ .allocator = a, .fixed = fixed };
    }
    pub fn deinit(self: *Setup) void {
        self.allocator.free(self.fixed);
        self.* = undefined;
    }
};

pub const Request = struct {
    allocator: std.mem.Allocator,
    fixed: []const M,
    main: []M,
    interaction: []M = &.{},
    dictionary: []Q = &.{},
    pub fn init(a: std.mem.Allocator, setup: *const Setup, counts: []const u64) !Request {
        if (counts.len != SEMANTIC_FACTS or setup.fixed.len != FIXED * SIZE) return error.InvalidPackedWordShiftShape;
        _ = try Bus.admitPositiveMass(counts);
        const main = try a.alloc(M, MAIN * SIZE);
        for (0..SIZE) |x| for (0..16) |r| {
            main[r * SIZE + physical(x, LOG)] = M.fromCanonical(@intCast(counts[16 * x + r]));
        };
        return .{ .allocator = a, .fixed = setup.fixed, .main = main };
    }
    pub fn deinit(self: *Request) void {
        self.allocator.free(self.main);
        self.allocator.free(self.interaction);
        self.allocator.free(self.dictionary);
        self.* = undefined;
    }
    pub fn generateInteraction(self: *Request, ch: Challenges) !Q {
        if (self.interaction.len != 0) return error.InvalidPackedWordShiftPhase;
        const a = self.allocator;
        const output = try a.alloc(M, INTERACTION * SIZE);
        errdefer a.free(output);
        const dictionary = try a.alloc(Q, SEMANTIC_FACTS);
        errdefer a.free(dictionary);
        const scratch = try a.alloc(Q, 16384);
        defer a.free(scratch);
        const denoms = scratch[0..8192];
        const products = scratch[8192..12288];
        const inverses = scratch[12288..16384];
        const prepared = Prepared.init(ch);
        var sum = Q.zero();
        var start: usize = 0;
        while (start < SIZE) : (start += 512) {
            var begin: usize = 0;
            while (begin < 512) : (begin += E.LANES) {
                var fields: [FIXED]E.PackedBase = undefined;
                for (&fields, 0..) |*field, c| {
                    var lanes: [E.LANES]M = undefined;
                    for (&lanes, 0..) |*v, lane| v.* = self.fixed[c * SIZE + physical(start + begin + lane, LOG)];
                    field.* = E.PackedBase.fromLanes(lanes);
                }
                for (0..16) |r| {
                    const d = prepared.denominatorFor(E.PackedBase, &fields, r);
                    for (0..E.LANES) |lane| denoms[(begin + lane) * 16 + r] = d.lane(lane);
                }
            }
            for (0..512) |i| for (0..8) |pair| {
                products[8 * i + pair] = denoms[16 * i + 2 * pair].mul(denoms[16 * i + 2 * pair + 1]);
            };
            try core.fields.batchInverseInPlace(Q, products, inverses);
            for (0..512) |i| {
                const row = physical(start + i, LOG);
                for (0..8) |pair| {
                    const inverse = inverses[8 * i + pair];
                    const inv_a = denoms[16 * i + 2 * pair + 1].mul(inverse);
                    const inv_b = denoms[16 * i + 2 * pair].mul(inverse);
                    dictionary[16 * (start + i) + 2 * pair] = inv_a;
                    dictionary[16 * (start + i) + 2 * pair + 1] = inv_b;
                    sum = sum.sub(inv_a.mulM31(self.main[(2 * pair) * SIZE + row])).sub(inv_b.mulM31(self.main[(2 * pair + 1) * SIZE + row]));
                    for (inverse.toM31Array(), 0..) |v, c| output[(4 * pair + c) * SIZE + row] = v;
                }
                for (sum.toM31Array(), 0..) |v, c| output[(32 + c) * SIZE + row] = v;
            }
        }
        for (sum.toM31Array(), 0..) |v, c| for (0..SIZE) |row| {
            output[(32 + c) * SIZE + row] = output[(32 + c) * SIZE + row].sub(v);
        };
        self.interaction = output;
        self.dictionary = dictionary;
        return sum;
    }
};
