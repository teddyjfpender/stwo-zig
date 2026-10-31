//! ONE polynomial authority for the concrete thin CPU's native/SIMD/OODS lanes.
//! Only register AND/OR/XOR execute. ROM/provider closure is mandatory; this
//! evaluator alone is not an execution verifier or an opcode-admission API.
const E = @import("../evaluation.zig");
const L = @import("layout.zig");
const P = @import("public.zig");
const Lookup = @import("lookup.zig");
const Profile = @import("profile.zig");
const Function = @import("../word16_v1/function_bus.zig");
pub fn functionTuple(comptime F: type, main: []const F) [13]F {
    var tuple: [13]F = undefined;
    tuple[0] = main[L.main.opcode];
    @memcpy(tuple[1..5], main[L.main.a..][0..4]);
    @memcpy(tuple[5..9], main[L.main.b..][0..4]);
    @memcpy(tuple[9..13], main[L.main.c..][0..4]);
    return tuple;
}
pub fn romTuple(comptime F: type, main: []const F) [16]F {
    var tuple: [16]F = undefined;
    tuple[0] = F.one();
    @memcpy(tuple[1..5], main[L.main.pc..][0..4]);
    @memcpy(tuple[5..9], main[L.main.next_pc..][0..4]);
    tuple[9] = main[L.main.opcode];
    @memcpy(tuple[10..13], main[L.main.registers..][0..3]);
    @memcpy(tuple[13..16], main[L.main.zero..][0..3]);
    return tuple;
}
pub fn romTupleProfile(comptime F: type, profile: Profile.Profile, main: []const F) [Profile.MAX_ROM]F {
    var result: [Profile.MAX_ROM]F = @splat(F.zero());
    @memcpy(result[0..16], &romTuple(F, main));
    if (profile == .alu_binary_v2) {
        const immediate = main[Profile.immediate];
        const branch = main[Profile.branch];
        result[16] = immediate;
        result[17] = branch;
        for (0..4) |limb| result[18 + limb] = immediate.mul(main[L.main.b + limb]);
        result[22] = branch.mul(main[L.main.c]);
    }
    return result;
}
pub fn tick(comptime F: type, index: F, slot: usize) F {
    return index.mul(P.literal(F, 4)).add(P.literal(F, @intCast(slot + 1)));
}
pub fn registerTuple(comptime F: type, fixed: []const F, main: []const F, slot: usize, after: bool) [6]F {
    var tuple: [6]F = undefined;
    tuple[0] = main[L.main.registers + slot];
    const value_start: usize = switch (slot) {
        0 => L.main.a,
        1 => L.main.b,
        2 => if (after) L.main.c else L.main.previous_rd,
        else => unreachable,
    };
    @memcpy(tuple[1..5], main[value_start..][0..4]);
    tuple[5] = if (after) tick(F, fixed[L.fixed.index], slot) else main[L.main.previous_clock + slot];
    return tuple;
}
fn range(comptime F: type, values: []const F, current: []const F, previous: []const F, at: usize, sum_at: usize, first: F, last: F, claim: E.Q, challenges: Lookup.RangeChallenges, sink: *E.SinkFor(F)) void {
    const S = E.SecureFor(F);
    const d0 = challenges.denominatorFor(F, values[0]);
    const d1 = challenges.denominatorFor(F, values[1]);
    const d2 = challenges.denominatorFor(F, values[2]);
    const inverse01 = E.secureFor(F, current, at);
    const inverse2 = E.secureFor(F, current, at + 4);
    sink.emit(d0.mul(d1).mul(inverse01).sub(S.one()));
    sink.emit(d2.mul(inverse2).sub(S.one()));
    const contribution = d0.add(d1).mul(inverse01).add(inverse2);
    Lookup.prefix(F, contribution, E.secureFor(F, current, sum_at), E.secureFor(F, previous, sum_at), first, last, claim, sink);
}
pub fn emitFor(comptime F: type, fixed: []const F, main: []const F, previous_main: []const F, current: []const F, previous: []const F, public: P.Public, claims: P.Claims, challenges: Lookup.Challenges, sink: *E.SinkFor(F)) void {
    emitProfileFor(F, .binary_v1, fixed, main, previous_main, current, previous, public, claims, challenges, sink);
}
pub fn emitProfileFor(comptime F: type, profile: Profile.Profile, fixed: []const F, main: []const F, previous_main: []const F, current: []const F, previous: []const F, public: P.Public, claims: P.Claims, challenges: Lookup.Challenges, sink: *E.SinkFor(F)) void {
    const first = fixed[L.fixed.first];
    const last = fixed[L.fixed.last];
    const index = fixed[L.fixed.index];
    const active = main[L.main.active];
    const inactive = F.one().sub(active);
    const not_first = F.one().sub(first);
    const previous_active = previous_main[L.main.active];
    E.booleanFor(F, sink, active);
    sink.emit(first.mul(active.sub(F.one())));
    sink.emit(last.mul(active));
    sink.emit(not_first.mul(active).mul(F.one().sub(previous_active)));
    // Only the publicsteps transition can end the active prefix. Index is a
    // domain-only fixed column; statementsteps never changes the fixed tree.
    sink.emit(not_first.mul(active.sub(previous_active)).mul(index.sub(E.qFor(F, public.steps))));
    const initial_pc = P.word(F, public.initial_pc);
    const final_pc = P.word(F, public.final_pc);
    for (0..4) |limb| {
        sink.emit(first.mul(main[L.main.pc + limb].sub(initial_pc[limb])));
        sink.emit(not_first.mul(main[L.main.pc + limb].sub(previous_main[L.main.next_pc + limb])));
        sink.emit(inactive.mul(main[L.main.next_pc + limb].sub(main[L.main.pc + limb])));
        sink.emit(last.mul(main[L.main.next_pc + limb].sub(final_pc[limb])));
    }
    for (0..3) |slot| {
        const enabled = main[L.main.enabled + slot];
        const zero = main[L.main.zero + slot];
        sink.emit(enabled.sub(active.mul(F.one().sub(zero))));
        const value: usize = switch (slot) {
            0 => L.main.a,
            1 => L.main.b,
            2 => L.main.previous_rd,
            else => unreachable,
        };
        const zero_weight = if (profile == .alu_binary_v2 and slot == 1) zero.mul(F.one().sub(main[Profile.immediate])) else zero;
        for (0..4) |limb| sink.emit(zero_weight.mul(main[value + limb]));
        sink.emit(main[L.main.previous_clock + slot].add(main[L.main.gap16 + slot]).add(E.qFor(F, 65536).mul(main[L.main.gap8 + slot])).sub(tick(F, index, slot).sub(F.one())));
        sink.emit(F.one().sub(enabled).mul(main[L.main.previous_clock + slot]));
    }
    var register_contribution = E.SecureFor(F).zero();
    for (0..3) |slot| {
        const before = challenges.register.denominatorFor(F, registerTuple(F, fixed, main, slot, false));
        const after = challenges.register.denominatorFor(F, registerTuple(F, fixed, main, slot, true));
        const inverse = E.secureFor(F, current, L.inter.register_inverses + 4 * slot);
        sink.emit(before.mul(after).mul(inverse).sub(E.SecureFor(F).one()));
        register_contribution = register_contribution.add(E.mulBaseFor(F, after.sub(before).mul(inverse), main[L.main.enabled + slot]));
    }
    Lookup.prefix(F, register_contribution, E.secureFor(F, current, L.inter.register_sum), E.secureFor(F, previous, L.inter.register_sum), first, last, claims.register, sink);
    Function.emitFor(F, functionTuple(F, main), active, first, last, E.secureFor(F, current, L.inter.function_inverse), E.secureFor(F, current, L.inter.function_sum), E.secureFor(F, previous, L.inter.function_sum), claims.function, challenges.function, sink);
    Lookup.single(F, challenges.rom.denominatorProfile(F, profile, romTupleProfile(F, profile, main)), active, E.secureFor(F, current, L.inter.rom_inverse), E.secureFor(F, current, L.inter.rom_sum), E.secureFor(F, previous, L.inter.rom_sum), first, last, claims.rom, sink);
    range(F, main[L.main.gap16..][0..3], current, previous, L.inter.range16_inverses, L.inter.range16_sum, first, last, claims.range16, challenges.range16, sink);
    range(F, main[L.main.gap8..][0..3], current, previous, L.inter.range8_inverses, L.inter.range8_sum, first, last, claims.range8, challenges.range8, sink);
}
