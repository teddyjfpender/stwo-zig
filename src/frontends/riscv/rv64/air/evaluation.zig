//! One concrete QM31 constraint authority for domain and OODS evaluation.
const std = @import("std");
const core = @import("stwo_core");
pub const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
pub const L = @import("layout.zig");
pub const O = @import("../decode.zig").Opcode;
pub const Fixed = [L.fixed.COUNT]Q;
pub const Main = [L.MAIN]Q;
/// A domain component borrows its already assigned ascending random powers.
/// Emission consumes them in reverse order, exactly matching Horner weights.
pub const WeightedAccumulator = struct {
    powers: []const Q,
    accumulation: Q = Q.zero(),
};
pub const Sink = struct {
    values: ?[]Q,
    count: usize = 0,
    accumulator: ?*core.air.accumulation.PointEvaluationAccumulator = null,
    weighted_accumulator: ?*WeightedAccumulator = null,
    scale: ?Q = null,
    /// Preserve every Horner weight while avoiding identically-zero work.
    pub fn zeros(self: *Sink, count: usize) void {
        if (self.values) |values| @memset(values[self.count..][0..count], Q.zero());
        if (self.accumulator) |accumulator| accumulator.accumulation = accumulator.accumulation.mul(accumulator.random_coeff.pow(count));
        self.count += count;
    }
    pub fn emit(self: *Sink, value: Q) void {
        if (self.values) |values| values[self.count] = value;
        if (self.accumulator != null or self.weighted_accumulator != null) {
            const scaled = if (self.scale) |scale| value.mul(scale) else value;
            if (self.accumulator) |accumulator| accumulator.accumulate(scaled);
            if (self.weighted_accumulator) |accumulator| {
                std.debug.assert(self.count < accumulator.powers.len);
                const power = accumulator.powers[accumulator.powers.len - 1 - self.count];
                accumulator.accumulation = accumulator.accumulation.add(power.mul(scaled));
            }
        }
        self.count += 1;
    }
};
pub const View = struct {
    f: *const Fixed,
    m: *const Main,
    pub fn op(self: View, opcode: O) Q {
        return self.f[L.fixed.opcode_start + @intFromEnum(opcode)];
    }
    pub fn sum(self: View, opcodes: []const O) Q {
        var result = Q.zero();
        for (opcodes) |opcode| result = result.add(self.op(opcode));
        return result;
    }
    pub fn byte(self: View, word: L.Word, index: usize) Q {
        return self.m[L.byte(word, index)];
    }
    pub fn bit(self: View, word: L.Word, index: usize) Q {
        return self.m[L.bit(word, index)];
    }
    pub fn carry(self: View, kind: L.Carry, index: usize) Q {
        return self.m[L.carry(kind, index)];
    }
};
pub fn q(value: u32) Q {
    return Q.fromBase(M.fromCanonical(value));
}
pub fn boolean(out: *Sink, value: Q) void {
    out.emit(value.mul(value.sub(Q.one())));
}

pub fn local(view: View, out: *Sink) void {
    localSupported(view, out, .{});
}

pub fn localSupported(view: View, out: *Sink, support: L.Support) void {
    ranges(view, out, support);
    @import("arithmetic_constraints.zig").evaluate(view, out);
    if (support.shifts) @import("shift_constraints.zig").evaluate(view, out) else out.zeros(2528);
    @import("memory_constraints.zig").evaluate(view, out);
    if (support.product) @import("product_constraints.zig").evaluate(view, out) else out.zeros(285);
    @import("division_constraints.zig").evaluate(view, out);
}

fn ranges(v: View, out: *Sink, support: L.Support) void {
    const one = Q.one();
    for (0..L.WORDS) |w| {
        if (!support.words[w]) {
            out.zeros(80);
            continue;
        }
        const word: L.Word = @enumFromInt(w);
        for (0..8) |i| {
            var reconstructed = Q.zero();
            for (0..8) |j| {
                const bit = v.bit(word, i * 8 + j);
                boolean(out, bit);
                reconstructed = reconstructed.add(bit.mul(q(@as(u32, 1) << @as(u5, @intCast(j)))));
            }
            out.emit(v.byte(word, i).sub(reconstructed));
            out.emit(one.sub(v.f[L.fixed.word_start + w]).mul(v.byte(word, i)));
        }
    }
    for (0..L.CARRIES) |i| {
        if (!support.carries[i]) {
            out.zeros(2);
            continue;
        }
        const value = v.m[L.carry_start + i];
        boolean(out, value);
        out.emit(one.sub(v.f[L.fixed.carry_start + i]).mul(value));
    }
    for (0..4) |slot| {
        if (!support.slots[slot]) {
            out.zeros(29);
            continue;
        }
        const enabled = v.f[L.fixed.slot_start + slot];
        for ([_]usize{ L.previousClock(slot), L.gap(slot) }) |start| {
            var reconstructed = Q.zero();
            for (0..L.CLOCK_BITS) |i| {
                const bit = v.m[start + 1 + i];
                boolean(out, bit);
                reconstructed = reconstructed.add(bit.mul(q(@as(u32, 1) << @as(u5, @intCast(i)))));
            }
            out.emit(v.m[start].sub(reconstructed));
            out.emit(one.sub(enabled).mul(v.m[start]));
        }
        out.emit(enabled.mul(v.m[L.previousClock(slot)].add(v.m[L.gap(slot)]).add(one).sub(v.f[L.fixed.tick_start + slot])));
    }
    for ([_]usize{ L.readable, L.writable, L.divisor_zero, L.sign_a, L.sign_b, L.negate, L.apply_negate, L.equal, L.taken }) |column| boolean(out, v.m[column]);
}
