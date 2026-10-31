//! One full64 bus-emitter authority for native OODS, packed domain and circuit
//! lanes. Family truths and the local REG boundary must close physically.
const E = @import("../evaluation.zig");
const L = @import("layout.zig");
const T = @import("types.zig");
const U = @import("tuples.zig");
const M = @import("stwo_core").fields.m31.M31;
const Q = E.Q;
const m = L.main;
pub const CONSTRAINTS = 55;
pub fn DenominatorsFor(comptime F: type) type {
    const S = E.SecureFor(F);
    return struct { before: [3]S, after: [3]S, function: S, rom: S, affine: [7]S };
}
pub fn WeightsFor(comptime F: type) type {
    return struct { registers: [3]F, function: F, rom: F, owner: F };
}
pub fn weightsFor(comptime F: type, row: []const F) WeightsFor(F) {
    return .{ .registers = row[m.enabled..][0..3].*, .function = row[m.function], .rom = row[m.active], .owner = row[m.active].sub(row[m.function]) };
}
pub fn denominatorsFor(comptime F: type, fixed: []const F, row: []const F, public: T.InputsFor(E.ConstFor(F)), ch: T.ChallengesFor(E.ConstFor(F))) DenominatorsFor(F) {
    var out: DenominatorsFor(F) = undefined;
    for (0..3) |slot| {
        out.before[slot] = ch.register.denominatorFor(F, U.register(F, fixed, row, slot, false));
        out.after[slot] = ch.register.denominatorFor(F, U.register(F, fixed, row, slot, true));
    }
    out.function = ch.function.denominatorFor(F, U.function(F, row));
    out.rom = ch.rom.denominatorFor(F, U.rom(F, row));
    out.affine[0] = ch.owner.denominatorFor(F, U.owner(F, fixed, row, E.scalarFor(F, public.epoch)));
    for (0..3) |slot| {
        out.affine[1 + slot] = ch.range16.denominatorFor(F, row[m.gap16 + slot]);
        out.affine[4 + slot] = ch.range8.denominatorFor(F, row[m.gap8 + slot]);
    }
    return out;
}
pub fn inverseDenominatorsFor(comptime F: type, ds: DenominatorsFor(F)) [9]E.SecureFor(F) {
    return .{ ds.before[0].mul(ds.after[0]), ds.before[1].mul(ds.after[1]), ds.before[2].mul(ds.after[2]), ds.function, ds.rom, ds.affine[0].mul(ds.affine[1]), ds.affine[2].mul(ds.affine[3]), ds.affine[4].mul(ds.affine[5]), ds.affine[6] };
}
pub fn contributionFor(comptime F: type, ds: DenominatorsFor(F), w: WeightsFor(F), inverse: [9]E.SecureFor(F)) E.SecureFor(F) {
    var out = E.SecureFor(F).zero();
    for (0..3) |slot| out = out.add(E.mulBaseFor(F, ds.after[slot].sub(ds.before[slot]).mul(inverse[slot]), w.registers[slot]));
    out = out.add(E.mulBaseFor(F, inverse[3], w.function)).add(E.mulBaseFor(F, inverse[4], w.rom));
    // OWNER has its own unit weight; every padded range query has weight one.
    const first_numerator = ds.affine[0].add(E.mulBaseFor(F, ds.affine[1], w.owner));
    out = out.add(first_numerator.mul(inverse[5]));
    out = out.add(ds.affine[2].add(ds.affine[3]).mul(inverse[6]));
    out = out.add(ds.affine[4].add(ds.affine[5]).mul(inverse[7]));
    return out.add(inverse[8]);
}
pub fn emitFor(comptime F: type, fixed: []const F, row: []const F, previous_main: []const F, current: []const F, previous: []const F, public: T.InputsFor(E.ConstFor(F)), claim: E.ConstFor(F), ch: T.ChallengesFor(E.ConstFor(F)), sink: *E.SinkFor(F)) void {
    const first = fixed[L.fixed.first];
    const last = fixed[L.fixed.last];
    const active = row[m.active];
    const one = F.one();
    // Same prefix semantics as the thin control, with steps itself a circuit
    // wire for external lanes. No native-only public count is captured.
    E.booleanFor(F, sink, active);
    sink.emit(first.mul(active.sub(one)));
    sink.emit(last.mul(active));
    sink.emit(one.sub(first).mul(active).mul(one.sub(previous_main[m.active])));
    sink.emit(one.sub(first).mul(active.sub(previous_main[m.active])).mul(fixed[0].sub(E.scalarFor(F, public.steps))));
    for (0..4) |limb| {
        sink.emit(first.mul(row[m.pc + limb].sub(E.scalarFor(F, public.initial_pc[limb]))));
        sink.emit(one.sub(first).mul(row[m.pc + limb].sub(previous_main[m.next_pc + limb])));
        sink.emit(one.sub(active).mul(row[m.next_pc + limb].sub(row[m.pc + limb])));
        sink.emit(last.mul(row[m.next_pc + limb].sub(E.scalarFor(F, public.final_pc[limb]))));
    }
    for (0..3) |slot| {
        const enabled = row[m.enabled + slot];
        sink.emit(enabled.sub(active.mul(one.sub(row[m.zero + slot]))));
        const start: usize = switch (slot) {
            0 => m.a,
            1 => m.b,
            2 => m.previous_rd,
            else => unreachable,
        };
        for (0..4) |limb| sink.emit(row[m.zero + slot].mul(row[start + limb]));
        sink.emit(row[m.previous_clock + slot].add(row[m.gap16 + slot]).add(E.qFor(F, 65536).mul(row[m.gap8 + slot])).sub(U.tick(F, fixed[0], @intCast(slot)).sub(one)));
        sink.emit(one.sub(enabled).mul(row[m.previous_clock + slot]));
    }
    const weights = weightsFor(F, row);
    E.booleanFor(F, sink, weights.function);
    E.booleanFor(F, sink, weights.owner);
    const ds = denominatorsFor(F, fixed, row, public, ch);
    var inverse: [9]E.SecureFor(F) = undefined;
    for (&inverse, 0..) |*value, i| value.* = E.secureFor(F, current, 4 * i);
    const inverse_denominators = inverseDenominatorsFor(F, ds);
    for (inverse_denominators, inverse) |d, value| sink.emit(d.mul(value).sub(E.SecureFor(F).one()));
    const sum = E.secureFor(F, current, L.inter.sum);
    sink.emit(sum.sub(E.secureFor(F, previous, L.inter.sum)).add(E.mulBaseFor(F, E.splatFor(F, claim), first)).sub(contributionFor(F, ds, weights, inverse)));
    sink.emit(E.mulBaseFor(F, sum, last));
}

/// Native witness acceleration uses the SAME tuple projections. No ISA
/// arithmetic, shape-dependent equations or host membership checks occur here.
fn dot(ch: anytype, values: anytype) Q {
    var out = ch.offset;
    for (ch.coefficients, values) |coefficient, value| out = out.sub(coefficient.mulM31(value));
    return out;
}
pub fn nativeDenominators(fixed: []const M, row: []const M, public: T.Inputs, ch: T.Challenges) DenominatorsFor(Q) {
    var out: DenominatorsFor(Q) = undefined;
    for (0..3) |slot| {
        out.before[slot] = dot(ch.register, U.register(M, fixed, row, slot, false));
        out.after[slot] = dot(ch.register, U.register(M, fixed, row, slot, true));
    }
    out.function = dot(ch.function, U.function(M, row));
    out.rom = dot(ch.rom, U.rom(M, row));
    out.affine[0] = dot(ch.owner, U.owner(M, fixed, row, M.fromCanonical(public.epoch)));
    for (0..3) |slot| {
        out.affine[1 + slot] = ch.range16.offset.sub(ch.range16.coefficient.mulM31(row[m.gap16 + slot]));
        out.affine[4 + slot] = ch.range8.offset.sub(ch.range8.coefficient.mulM31(row[m.gap8 + slot]));
    }
    return out;
}
pub fn nativeContribution(ds: DenominatorsFor(Q), row: []const M, inverse: [9]Q) Q {
    const w = weightsFor(M, row);
    return contributionFor(Q, ds, .{ .registers = .{ Q.fromBase(w.registers[0]), Q.fromBase(w.registers[1]), Q.fromBase(w.registers[2]) }, .function = Q.fromBase(w.function), .rom = Q.fromBase(w.rom), .owner = Q.fromBase(w.owner) }, inverse);
}
