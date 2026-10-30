const std = @import("std");
const E = @import("../evaluation.zig");
const Encoding = @import("../encoding.zig");
const Q = E.Q;
const L = E.L;

test "compiled logical inflation overwrites poisoned live coordinates and retains permanent zeros" {
    var all: [63]E.O = undefined;
    for (&all, 0..) |*op, i| op.* = @enumFromInt(i);
    const cases = [_][]const E.O{ &all, &.{.ADDI}, &.{ .XOR, .SRA, .LD, .SD }, &.{ .MULHU, .DIVU, .REMUW } };
    var prng = std.Random.DefaultPrng.init(0x494e464c41544544);
    const rng = prng.random();
    for (cases) |opcodes| {
        const plan = Encoding.Plan.fromOpcodes(opcodes);
        const compiled = plan.inflation();
        var live: [L.MAIN]bool = @splat(false);
        for (compiled.sources[0..compiled.source_count]) |source| live[source.logical] = true;
        for (compiled.bytes[0..compiled.byte_count]) |byte| live[byte.logical] = true;
        if (compiled.product) for (0..16) |i| {
            live[L.productCarry(i)] = true;
        };
        for (compiled.clock_slots, 0..) |enabled, slot| if (enabled) {
            live[L.previousClock(slot)] = true;
            live[L.gap(slot)] = true;
        };
        var reused: E.Main = @splat(Q.zero());
        var physical: [L.MAIN]Q = undefined;
        for (0..12) |round| {
            for (physical[0..plan.main_count]) |*value| value.* = if (round % 3 == 0) Q.zero() else randomQ(rng);
            // A reused destination may contain any previous row's live values.
            // Poison all of them so a missed overwrite cannot hide in zeros.
            for (&reused, live) |*value, written| if (written) {
                value.* = randomQ(rng);
            };
            compiled.apply(physical[0..plan.main_count], &reused);
            const legacy = reference(&plan, physical[0..plan.main_count]);
            const fresh = plan.inflateMain(physical[0..plan.main_count]);
            for (reused, legacy, fresh) |actual, expected, independent| {
                try std.testing.expect(actual.eql(expected));
                try std.testing.expect(actual.eql(independent));
            }
        }
    }
}
// Retained pre-optimization substitution, evaluated independently of the map.
pub fn reference(plan: *const Encoding.Plan, physical: []const Q) E.Main {
    var logical: E.Main = @splat(Q.zero());
    for (plan.main_sources[0..plan.main_count], physical) |c, value| if (c < L.MAIN) {
        logical[c] = value;
    };
    for (0..L.WORDS) |w| {
        const word: L.Word = @enumFromInt(w);
        for (0..8) |i| if (plan.support.words[w] and plan.byte_bits[w][i]) {
            logical[L.byte(word, i)] = reconstruct(&logical, L.bit(word, i * 8), 8);
        };
    }
    for (0..16) |i| {
        const start = L.productCarry(i);
        logical[start] = if (plan.compact_product_carries) logical[start + 1].add(reconstruct(&logical, start + 9, 3).mul(E.q(256))) else reconstruct(&logical, start + 1, 11);
    }
    for (0..4) |slot| for ([_]usize{ L.previousClock(slot), L.gap(slot) }) |start| {
        logical[start] = if (plan.wide_clocks) logical[start + 1].add(logical[start + 2].mul(E.q(256))).add(logical[start + 3].mul(E.q(65536))) else reconstruct(&logical, start + 1, L.CLOCK_BITS);
    };
    return logical;
}
fn reconstruct(logical: *const E.Main, start: usize, count: usize) Q {
    var sum = Q.zero();
    for (0..count) |i| sum = sum.add(logical[start + i].mul(E.q(@as(u32, 1) << @as(u5, @intCast(i)))));
    return sum;
}
fn randomQ(rng: std.Random) Q {
    const p = @import("stwo_core").fields.m31.Modulus;
    return Q.fromU32Unchecked(rng.int(u32) % p, rng.int(u32) % p, rng.int(u32) % p, rng.int(u32) % p);
}
