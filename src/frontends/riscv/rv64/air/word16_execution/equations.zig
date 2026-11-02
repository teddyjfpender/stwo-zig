//! One full64 bus-emitter authority for native OODS, packed domain and circuit
//! lanes. Family truths and the local REG boundary must close physically.
const E = @import("../evaluation.zig");
const L = @import("layout.zig");
const T = @import("types.zig");
const U = @import("tuples.zig");
const M = @import("stwo_core").fields.m31.M31;
const Q = E.Q;
const m = L.main;
const Tables = @import("../providers/tables.zig");
pub const CONSTRAINTS = 52;
/// Fused-tail encoding: 8 witness residuals + 1 fused prefix + last*S.
pub const FUSED_CONSTRAINTS = CONSTRAINTS - 1;
pub fn constraintCount(fused: bool) usize {
    return if (fused) FUSED_CONSTRAINTS else CONSTRAINTS;
}
/// Byte-pair encoding: 7 fraction residuals + 1 fused pair prefix + last*S.
pub const PAIR_CONSTRAINTS = MAIN_CONSTRAINTS + L.pairs.WITNESSES + 2;
pub fn constraintCountFor(fused: bool, pairs: bool) usize {
    return if (pairs) PAIR_CONSTRAINTS else constraintCount(fused);
}
/// The AND relation's challenges; the byte pair is its tagged tuple (x, y, 0, 1).
pub fn PairChallengesFor(comptime C: type) type {
    return Tables.ChallengesFor(C);
}
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
/// Exact original MAIN-only residual prefix; local relation constraints are separate.
pub const MAIN_CONSTRAINTS = CONSTRAINTS - 11;
pub fn emitMainFor(comptime F: type, fixed: []const F, row: []const F, previous_main: []const F, public: T.InputsFor(E.ConstFor(F)), sink: *E.SinkFor(F)) void {
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
        // ROM authenticates 1-enabled as the instruction's zero-register flag
        // on active rows. Padding has enabled=0. No independent zero witness
        // is needed, and no additional Boolean/range provider is introduced.
        sink.emit(one.sub(active).mul(enabled));
        const start: usize = switch (slot) {
            0 => m.a,
            1 => m.b,
            2 => m.previous_rd,
            else => unreachable,
        };
        for (0..4) |limb| sink.emit(one.sub(enabled).mul(row[start + limb]));
        sink.emit(one.sub(enabled).mul(U.previousClock(F, fixed[0], row, @intCast(slot))));
    }
    const weights = weightsFor(F, row);
    E.booleanFor(F, sink, weights.function);
    E.booleanFor(F, sink, weights.owner);
}

pub fn emitFor(comptime F: type, fixed: []const F, row: []const F, previous_main: []const F, current: []const F, previous: []const F, public: T.InputsFor(E.ConstFor(F)), claim: E.ConstFor(F), ch: T.ChallengesFor(E.ConstFor(F)), sink: *E.SinkFor(F)) void {
    emitMainFor(F, fixed, row, previous_main, public, sink);
    const first = fixed[L.fixed.first];
    const last = fixed[L.fixed.last];
    const weights = weightsFor(F, row);
    const ds = denominatorsFor(F, fixed, row, public, ch);
    var inverse: [9]E.SecureFor(F) = undefined;
    for (&inverse, 0..) |*value, i| value.* = E.secureFor(F, current, 4 * i);
    const inverse_denominators = inverseDenominatorsFor(F, ds);
    for (inverse_denominators, inverse) |d, value| sink.emit(d.mul(value).sub(E.SecureFor(F).one()));
    const sum = E.secureFor(F, current, L.inter.sum);
    sink.emit(sum.sub(E.secureFor(F, previous, L.inter.sum)).add(E.mulBaseFor(F, E.splatFor(F, claim), first)).sub(contributionFor(F, ds, weights, inverse)));
    sink.emit(E.mulBaseFor(F, sum, last));
}

/// Fused-tail contribution of the eight committed witnesses. Every term has
/// degree <= 2, so multiplying the prefix residual by the affine U8 tail
/// denominator stays within degree 3. The tail 1/affine[6] is NOT included.
pub fn fusedContributionFor(comptime F: type, ds: DenominatorsFor(F), w: WeightsFor(F), witness: [L.fused.WITNESSES]E.SecureFor(F)) E.SecureFor(F) {
    var out = witness[0].add(witness[1]).add(witness[2]);
    out = out.add(E.mulBaseFor(F, witness[3], w.function)).add(E.mulBaseFor(F, witness[4], w.rom));
    out = out.add(witness[5]);
    out = out.add(ds.affine[2].add(ds.affine[3]).mul(witness[6]));
    return out.add(ds.affine[4].add(ds.affine[5]).mul(witness[7]));
}
/// Opt-in fused-tail CPU interaction (36 columns, FUSED_CONSTRAINTS residuals).
/// Same LogUp statement and per-row increment as `emitFor`:
/// - REG slots are fraction witnesses R*before*after = w*(after-before);
/// - OWNER+U16 is a fraction witness F*d0*d1 = d0 + w_owner*d1, because its
///   numerator is affine and the inverse form would make the fused residual
///   degree four;
/// - FUNCTION, ROM, U16+U16 and U8+U8 keep strict inverses;
/// - the U8 single is (S-S_prev+claim*first-C8)*d6 - 1, strict at d6=0.
pub fn emitFusedFor(comptime F: type, fixed: []const F, row: []const F, previous_main: []const F, current: []const F, previous: []const F, public: T.InputsFor(E.ConstFor(F)), claim: E.ConstFor(F), ch: T.ChallengesFor(E.ConstFor(F)), sink: *E.SinkFor(F)) void {
    emitMainFor(F, fixed, row, previous_main, public, sink);
    const S = E.SecureFor(F);
    const first = fixed[L.fixed.first];
    const last = fixed[L.fixed.last];
    const w = weightsFor(F, row);
    const ds = denominatorsFor(F, fixed, row, public, ch);
    var witness: [L.fused.WITNESSES]S = undefined;
    for (&witness, 0..) |*value, i| value.* = E.secureFor(F, current, 4 * i);
    for (0..3) |slot| sink.emit(witness[slot].mul(ds.before[slot]).mul(ds.after[slot]).sub(E.mulBaseFor(F, ds.after[slot].sub(ds.before[slot]), w.registers[slot])));
    sink.emit(ds.function.mul(witness[3]).sub(S.one()));
    sink.emit(ds.rom.mul(witness[4]).sub(S.one()));
    sink.emit(witness[5].mul(ds.affine[0]).mul(ds.affine[1]).sub(ds.affine[0].add(E.mulBaseFor(F, ds.affine[1], w.owner))));
    sink.emit(ds.affine[2].mul(ds.affine[3]).mul(witness[6]).sub(S.one()));
    sink.emit(ds.affine[4].mul(ds.affine[5]).mul(witness[7]).sub(S.one()));
    const sum = E.secureFor(F, current, L.fused.sum);
    const step = sum.sub(E.secureFor(F, previous, L.fused.sum)).add(E.mulBaseFor(F, E.splatFor(F, claim), first)).sub(fusedContributionFor(F, ds, w, witness));
    sink.emit(step.mul(ds.affine[6]).sub(S.one()));
    sink.emit(E.mulBaseFor(F, sum, last));
}

/// Byte-pair lookup denominators (gap8_0, gap8_1) and (gap8_2, 0), each the
/// tagged AND-relation tuple (x, y, 0, 1). Affine in MAIN.
pub fn pairDenominatorsFor(comptime F: type, row: []const F, ch: PairChallengesFor(E.ConstFor(F))) [2]E.SecureFor(F) {
    return .{ Tables.pairDenominatorFor(F, ch, row[m.gap8], row[m.gap8 + 1]), Tables.pairDenominatorFor(F, ch, row[m.gap8 + 2], F.zero()) };
}
/// Sum of the seven committed pair-mode witnesses (all degree one).
pub fn pairContributionFor(comptime F: type, witness: [L.pairs.WITNESSES]E.SecureFor(F)) E.SecureFor(F) {
    var out = witness[0];
    for (witness[1..]) |value| out = out.add(value);
    return out;
}
/// Opt-in byte-pair CPU interaction (32 columns, PAIR_CONSTRAINTS residuals).
/// Same per-row increment as `emitFusedFor` except that the three U8 range
/// fractions become two byte-pair fractions of the AND relation:
/// - REG slots: R*before*after = w*(after-before) (as fused);
/// - FUNCTION: G*d_fn = function, ROM: H*d_rom = active (quadratic d, degree 3);
/// - OWNER+U16: F*d0*d1 = d0 + w_owner*d1 (as fused);
/// - U16+U16: K*d2*d3 = d2 + d3;
/// - both byte pairs fused: (S-S_prev+claim*first-C7)*p0*p1 - (p0+p1) = 0,
///   where C7 is the sum of the seven witnesses (degree one), so degree 3.
pub fn emitPairsFor(comptime F: type, fixed: []const F, row: []const F, previous_main: []const F, current: []const F, previous: []const F, public: T.InputsFor(E.ConstFor(F)), claim: E.ConstFor(F), ch: T.ChallengesFor(E.ConstFor(F)), pair_ch: PairChallengesFor(E.ConstFor(F)), sink: *E.SinkFor(F)) void {
    emitMainFor(F, fixed, row, previous_main, public, sink);
    const S = E.SecureFor(F);
    const first = fixed[L.fixed.first];
    const last = fixed[L.fixed.last];
    const w = weightsFor(F, row);
    const ds = denominatorsFor(F, fixed, row, public, ch);
    const p = pairDenominatorsFor(F, row, pair_ch);
    var witness: [L.pairs.WITNESSES]S = undefined;
    for (&witness, 0..) |*value, i| value.* = E.secureFor(F, current, 4 * i);
    for (0..3) |slot| sink.emit(witness[slot].mul(ds.before[slot]).mul(ds.after[slot]).sub(E.mulBaseFor(F, ds.after[slot].sub(ds.before[slot]), w.registers[slot])));
    sink.emit(ds.function.mul(witness[3]).sub(E.mulBaseFor(F, S.one(), w.function)));
    sink.emit(ds.rom.mul(witness[4]).sub(E.mulBaseFor(F, S.one(), w.rom)));
    sink.emit(witness[5].mul(ds.affine[0]).mul(ds.affine[1]).sub(ds.affine[0].add(E.mulBaseFor(F, ds.affine[1], w.owner))));
    sink.emit(witness[6].mul(ds.affine[2]).mul(ds.affine[3]).sub(ds.affine[2].add(ds.affine[3])));
    const sum = E.secureFor(F, current, L.pairs.sum);
    const step = sum.sub(E.secureFor(F, previous, L.pairs.sum)).add(E.mulBaseFor(F, E.splatFor(F, claim), first)).sub(pairContributionFor(F, witness));
    sink.emit(step.mul(p[0]).mul(p[1]).sub(p[0].add(p[1])));
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
/// Honest native fused witnesses (tests/repair only; the prover fill batch-inverts).
pub fn nativeFusedWitnesses(ds: DenominatorsFor(Q), row: []const M) ![L.fused.WITNESSES]Q {
    const w = weightsFor(M, row);
    var out: [L.fused.WITNESSES]Q = undefined;
    for (0..3) |slot| out[slot] = ds.after[slot].sub(ds.before[slot]).mul(try ds.before[slot].mul(ds.after[slot]).inv()).mulM31(w.registers[slot]);
    out[3] = try ds.function.inv();
    out[4] = try ds.rom.inv();
    out[5] = ds.affine[0].add(ds.affine[1].mulM31(w.owner)).mul(try ds.affine[0].mul(ds.affine[1]).inv());
    out[6] = try ds.affine[2].mul(ds.affine[3]).inv();
    out[7] = try ds.affine[4].mul(ds.affine[5]).inv();
    return out;
}
/// Honest native pair-mode witnesses (tests/repair only).
pub fn nativePairWitnesses(ds: DenominatorsFor(Q), row: []const M) ![L.pairs.WITNESSES]Q {
    const w = weightsFor(M, row);
    const fused = try nativeFusedWitnesses(ds, row);
    var out: [L.pairs.WITNESSES]Q = undefined;
    @memcpy(out[0..3], fused[0..3]);
    out[3] = fused[3].mulM31(w.function);
    out[4] = fused[4].mulM31(w.rom);
    out[5] = fused[5];
    out[6] = ds.affine[2].add(ds.affine[3]).mul(fused[6]);
    return out;
}
pub fn nativePairDenominators(row: []const M, ch: Tables.Challenges) [2]Q {
    const g = [3]Q{ Q.fromBase(row[m.gap8]), Q.fromBase(row[m.gap8 + 1]), Q.fromBase(row[m.gap8 + 2]) };
    return .{ Tables.pairDenominatorFor(Q, ch, g[0], g[1]), Tables.pairDenominatorFor(Q, ch, g[2], Q.zero()) };
}
/// Exact per-row prefix increment of the pair encoding, both pairs included.
pub fn nativePairContribution(row: []const M, ch: Tables.Challenges, witness: [L.pairs.WITNESSES]Q) !Q {
    const p = nativePairDenominators(row, ch);
    return pairContributionFor(Q, witness).add(try p[0].inv()).add(try p[1].inv());
}
/// Exact per-row prefix increment of the fused encoding, tail included.
pub fn nativeFusedContribution(ds: DenominatorsFor(Q), row: []const M, witness: [L.fused.WITNESSES]Q) !Q {
    const w = weightsFor(M, row);
    return fusedContributionFor(Q, ds, .{ .registers = .{ Q.fromBase(w.registers[0]), Q.fromBase(w.registers[1]), Q.fromBase(w.registers[2]) }, .function = Q.fromBase(w.function), .rom = Q.fromBase(w.rom), .owner = Q.fromBase(w.owner) }, witness).add(try ds.affine[6].inv());
}
