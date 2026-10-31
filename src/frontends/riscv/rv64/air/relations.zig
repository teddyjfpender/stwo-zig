//! Authenticated full-width state chains, with challenges after main commitment.
const E = @import("evaluation.zig");
const Q = E.Q;
const L = E.L;
const core = @import("stwo_core");
const S = @import("statement.zig");
pub const ARITY = 20;
pub const Tuple = [ARITY]Q;
pub const Challenges = struct {
    offset: Q,
    coefficients: [ARITY]Q,

    pub fn draw(channel: *@import("protocol.zig").Channel) Challenges {
        channel.mixU32s(&.{ 0x52563634, 0x53544154, 1 });
        var result: Challenges = undefined;
        result.offset = channel.drawSecureFelt();
        for (&result.coefficients) |*coefficient| coefficient.* = channel.drawSecureFelt();
        return result;
    }

    pub fn denominator(self: Challenges, entry: Tuple) Q {
        return self.denominatorFor(Q, entry);
    }
    pub fn denominatorFor(self: Challenges, comptime F: type, entry: [ARITY]F) E.SecureFor(F) {
        return E.denominatorFor(F, self.offset, &self.coefficients, &entry, false);
    }
};

pub fn tuple(v: E.View, slot: usize, before: bool) Tuple {
    return tupleFor(Q, v, slot, before);
}
pub fn tupleFor(comptime F: type, v: E.ViewFor(F), slot: usize, before: bool) [ARITY]F {
    var result: [ARITY]F = @splat(F.zero());
    if (slot < 3) {
        result[1] = v.f[
            switch (slot) {
                0 => L.fixed.rs1,
                1 => L.fixed.rs2,
                else => L.fixed.rd,
            }
        ];
        const word: L.Word = switch (slot) {
            0 => .a,
            1 => .b,
            else => if (before) .previous_rd else .result,
        };
        for (0..8) |i| result[10 + i] = v.byte(word, i);
        result[18] = F.one();
        result[19] = F.one();
    } else {
        result[0] = F.one();
        for (0..8) |i| result[1 + i] = v.byte(.address, i);
        result[1] = result[1].sub(v.bit(.address, 0)).sub(v.bit(.address, 1).mul(E.qFor(F, 2))).sub(v.bit(.address, 2).mul(E.qFor(F, 4)));
        for (0..8) |i| result[10 + i] = v.byte(if (before) .memory_before else .memory_after, i);
        result[18] = v.m[L.readable];
        result[19] = v.m[L.writable];
    }
    result[9] = if (before) v.m[L.previousClock(slot)] else v.f[L.fixed.tick_start + slot];
    return result;
}

pub fn boundaryTuple(space: u32, address: u64, clock: u32, value: u64, readable: bool, writable: bool) Tuple {
    var result: Tuple = @splat(Q.zero());
    result[0] = E.q(space);
    result[9] = E.q(clock);
    for (0..8) |i| {
        result[1 + i] = E.q(@intCast((address >> @as(u6, @intCast(8 * i))) & 255));
        result[10 + i] = E.q(@intCast((value >> @as(u6, @intCast(8 * i))) & 255));
    }
    result[18] = E.q(@intFromBool(readable));
    result[19] = E.q(@intFromBool(writable));
    return result;
}

/// Derived only from independently expected public state and bounded clocks.
pub fn expected(public: S.Statement, metadata: S.Metadata, challenges: Challenges) !Q {
    var result = Q.zero();
    for (1..32) |reg| {
        const initial = boundaryTuple(0, reg, 0, public.initial_registers[reg], true, true);
        const final = boundaryTuple(0, reg, metadata.register_clocks[reg], public.final_registers[reg], true, true);
        result = result.add(try challenges.denominator(initial).inv()).sub(try challenges.denominator(final).inv());
    }
    for (public.memory, metadata.memory_clocks) |cell, clock| {
        const initial = boundaryTuple(1, cell.address, 0, cell.initial, cell.readable, cell.writable);
        const final = boundaryTuple(1, cell.address, clock, cell.final, cell.readable, cell.writable);
        result = result.add(try challenges.denominator(initial).inv()).sub(try challenges.denominator(final).inv());
    }
    return result;
}

pub fn secure(columns: *const [L.INTERACTION]Q, offset: usize) Q {
    return secureFor(Q, columns, offset);
}
pub fn secureFor(comptime F: type, columns: *const [L.INTERACTION]F, offset: usize) E.SecureFor(F) {
    return E.secureFor(F, columns, offset);
}

pub fn evaluate(v: E.View, current: *const [L.INTERACTION]Q, previous: *const [L.INTERACTION]Q, challenges: Challenges, target: Q, out: *E.Sink) void {
    return evaluateFor(Q, v, current, previous, challenges, target, out);
}
pub fn evaluateFor(comptime F: type, v: E.ViewFor(F), current: *const [L.INTERACTION]F, previous: *const [L.INTERACTION]F, challenges: Challenges, target: Q, out: *E.SinkFor(F)) void {
    var contribution = E.SecureFor(F).zero();
    for (0..4) |slot| {
        const active = v.f[L.fixed.slot_start + slot];
        const before = secureFor(F, current, slot * 8);
        const after = secureFor(F, current, slot * 8 + 4);
        out.emit(challenges.denominatorFor(F, tupleFor(F, v, slot, true)).mul(before).sub(E.liftFor(F, active)));
        out.emit(challenges.denominatorFor(F, tupleFor(F, v, slot, false)).mul(after).sub(E.liftFor(F, active)));
        out.emit(E.mulBaseFor(F, before, F.one().sub(active)));
        out.emit(E.mulBaseFor(F, after, F.one().sub(active)));
        contribution = contribution.add(before).sub(after);
    }
    const sum = secureFor(F, current, 32);
    const prior = secureFor(F, previous, 32);
    out.emit(sum.sub(E.mulBaseFor(F, prior, F.one().sub(v.f[L.fixed.first]))).sub(contribution));
    out.emit(E.mulBaseFor(F, sum.sub(E.splatFor(F, target)), v.f[L.fixed.last]));
}
