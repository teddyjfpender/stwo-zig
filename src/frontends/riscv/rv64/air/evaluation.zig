//! Shared equations for packed base-field domain lanes, secure OODS values and
//! external verifier lanes; one dispatch hub for every RV64 constraint lane.
const std = @import("std");
const core = @import("stwo_core");
pub const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
pub const L = @import("layout.zig");
pub const O = @import("../decode.zig").Opcode;
pub const Fixed = [L.fixed.COUNT]Q;
pub const Main = [L.MAIN]Q;
pub const PackedFields = @import("packed_fields.zig");
pub const PackedBase = PackedFields.PackedBase;
pub const PackedSecure = PackedFields.PackedSecure;
pub const LANES = PackedFields.LANES;

pub const lane = @import("lane.zig");
pub const isExternalLane = lane.isExternal;
pub const assertExternalLane = lane.assertExternalLane;

/// Lane families: the QM31 verifier lane and the two packed SIMD domain lanes
/// share QM31-valued constants; an external lane supplies its own constants.
pub fn isNativeLane(comptime F: type) bool {
    return F == Q or F == PackedBase or F == PackedSecure;
}
fn assertLane(comptime F: type) void {
    comptime {
        if (!isNativeLane(F) and !isExternalLane(F)) @compileError("unsupported RV64 arithmetic lane");
    }
}
/// Type of every non-mask scalar (challenge, claim, lifted public) entering a
/// constraint instantiated over trace lane F.
pub fn ConstFor(comptime F: type) type {
    assertLane(F);
    return if (isExternalLane(F)) F else Q;
}
/// Component storage lane: `Q` for the native family, an external lane itself.
pub fn assertConstLane(comptime Lane: type) void {
    comptime {
        if (Lane != Q and !isExternalLane(Lane)) @compileError("unsupported RV64 constant lane");
    }
}
/// Public base-field counts: native integers, or lane values for an external lane.
pub fn CountFor(comptime Lane: type) type {
    assertConstLane(Lane);
    return if (isExternalLane(Lane)) Lane else u32;
}
/// Native default for a count field; an external lane assigns every count
/// explicitly (the batch-level lift does), so its default is left undefined.
pub fn countDefault(comptime Lane: type, comptime value: u32) CountFor(Lane) {
    return if (isExternalLane(Lane)) undefined else value;
}
pub fn NativeOr(comptime Lane: type, comptime Native: type) type {
    assertConstLane(Lane);
    return if (isExternalLane(Lane)) Lane else Native;
}
/// Derived Boolean publics (`count != 0`) that a native evaluator computes and
/// an external lane must receive as a wire. Absent until the lane supplies it.
pub fn FlagFor(comptime Lane: type) type {
    assertConstLane(Lane);
    return if (isExternalLane(Lane)) ?Lane else void;
}
pub fn flagDefault(comptime Lane: type) FlagFor(Lane) {
    return if (isExternalLane(Lane)) null else {};
}
/// Call-span publics (service call count and first call ID): native integers,
/// or lane wires together with the derived `calls != 0` Boolean wire.
pub fn CallSpanFor(comptime Lane: type) type {
    assertConstLane(Lane);
    if (isExternalLane(Lane)) return struct { calls: Lane, first_id: Lane, nonempty: Lane };
    return struct { calls: u32, first_id: u32 = 1 };
}
pub inline fn callsFor(comptime F: type, span: CallSpanFor(ConstFor(F))) F {
    return scalarFor(F, span.calls);
}
pub inline fn firstIdFor(comptime F: type, span: CallSpanFor(ConstFor(F))) F {
    return scalarFor(F, span.first_id);
}
pub inline fn lastIdFor(comptime F: type, span: CallSpanFor(ConstFor(F))) F {
    if (comptime isExternalLane(F)) return span.first_id.add(span.calls).sub(F.one());
    return qFor(F, span.first_id + span.calls - 1);
}
pub inline fn nonemptyFor(comptime F: type, span: CallSpanFor(ConstFor(F))) F {
    if (comptime isExternalLane(F)) return span.nonempty;
    return qFor(F, @intFromBool(span.calls != 0));
}
pub inline fn scalarFor(comptime F: type, value: anytype) F {
    if (comptime isExternalLane(F)) return value;
    return qFor(F, @intCast(value));
}
pub inline fn scalarMinusOneFor(comptime F: type, value: anytype) F {
    if (comptime isExternalLane(F)) return value.sub(F.one());
    return qFor(F, @intCast(value - 1));
}
/// `count != 0` as a lane value: computed natively, read from the flag externally.
pub fn nonzeroFor(comptime F: type, count: anytype, flag: FlagFor(ConstFor(F))) !F {
    if (comptime isExternalLane(F)) return flag orelse error.MissingRv64LaneFlag;
    return qFor(F, @intFromBool(count != 0));
}

pub fn FixedFor(comptime F: type) type {
    return if (F == Q) Fixed else [L.fixed.COUNT]F;
}
pub fn MainFor(comptime F: type) type {
    return if (F == Q) Main else [L.MAIN]F;
}
pub fn ViewFor(comptime F: type) type {
    if (F == Q) return View;
    assertLane(F);
    return struct {
        const Self = @This();
        f: *const FixedFor(F),
        m: *const MainFor(F),
        pub inline fn op(self: Self, opcode: O) F {
            return self.f[L.fixed.opcode_start + @intFromEnum(opcode)];
        }
        pub inline fn sum(self: Self, opcodes: []const O) F {
            var result = F.zero();
            for (opcodes) |opcode| result = result.add(self.op(opcode));
            return result;
        }
        pub inline fn byte(self: Self, word: L.Word, index: usize) F {
            return self.m[L.byte(word, index)];
        }
        pub inline fn bit(self: Self, word: L.Word, index: usize) F {
            return self.m[L.bit(word, index)];
        }
        pub inline fn carry(self: Self, kind: L.Carry, index: usize) F {
            return self.m[L.carry(kind, index)];
        }
    };
}
pub fn SecureFor(comptime F: type) type {
    if (F == Q) return Q;
    if (F == PackedBase or F == PackedSecure) return PackedSecure;
    if (isExternalLane(F)) return F;
    @compileError("unsupported RV64 arithmetic lane");
}
pub const secureTypeFor = SecureFor;
pub inline fn qFor(comptime F: type, value: u32) F {
    if (F == Q) return q(value);
    if (F == PackedBase) return PackedBase.fromCanonical(value);
    if (F == PackedSecure) return PackedSecure.splat(q(value));
    if (comptime isExternalLane(F)) return F.fromU32(value);
    @compileError("unsupported RV64 arithmetic lane");
}
pub inline fn liftFor(comptime F: type, value: F) SecureFor(F) {
    if (F == PackedBase) return PackedSecure.fromBase(value);
    return value;
}
/// A constant of the lane's constant family as a secure lane value.
pub inline fn splatFor(comptime F: type, value: ConstFor(F)) SecureFor(F) {
    if (F == PackedBase or F == PackedSecure) return PackedSecure.splat(value);
    return value;
}
pub inline fn mulBaseFor(comptime F: type, secure: SecureFor(F), base: F) SecureFor(F) {
    if (F == PackedBase) return secure.mulBase(base);
    return secure.mul(base);
}
pub inline fn secureFromCoordinatesFor(comptime F: type, values: [4]F) SecureFor(F) {
    if (F == Q) return Q.fromPartialEvals(values);
    if (F == PackedBase) return PackedSecure.fromCoordinates(values);
    if (F == PackedSecure) return PackedSecure.fromPartialEvals(values);
    if (comptime isExternalLane(F)) return F.fromPartialEvals(values);
    @compileError("unsupported RV64 arithmetic lane");
}
pub inline fn secureFor(comptime F: type, coordinates: []const F, index: usize) SecureFor(F) {
    return secureFromCoordinatesFor(F, coordinates[index..][0..4].*);
}
pub inline fn denominatorFor(comptime F: type, offset: ConstFor(F), coefficients: []const ConstFor(F), tuple: []const F, comptime subtract: bool) SecureFor(F) {
    std.debug.assert(coefficients.len == tuple.len);
    var result = splatFor(F, offset);
    for (coefficients, tuple) |coefficient, value| {
        const term = mulBaseFor(F, splatFor(F, coefficient), value);
        result = if (subtract) result.sub(term) else result.add(term);
    }
    return result;
}
pub fn SinkFor(comptime F: type) type {
    if (F == Q) return Sink;
    if (F == PackedBase or F == PackedSecure) return PackedSink;
    if (isExternalLane(F)) return lane.Sink(F);
    @compileError("unsupported RV64 arithmetic lane");
}
pub fn WeightedAccumulatorFor(comptime F: type) type {
    if (F == Q) return WeightedAccumulator;
    if (F == PackedBase or F == PackedSecure) return PackedWeightedAccumulator;
    @compileError("unsupported RV64 arithmetic lane");
}
pub const PackedWeightedAccumulator = struct {
    powers: []const Q,
    accumulation: PackedSecure = PackedSecure.zero(),
};
pub const PackedSink = struct {
    values: ?[]PackedSecure = null,
    count: usize = 0,
    weighted_accumulator: ?*PackedWeightedAccumulator = null,
    scale: ?PackedSecure = null,
    pub inline fn zeros(self: *PackedSink, count: usize) void {
        if (self.values) |values| @memset(values[self.count..][0..count], PackedSecure.zero());
        self.count += count;
    }
    /// Mixed base/secure equations share one emission counter and one reverse
    /// random-power sequence. Base residuals never perform a secure product.
    pub inline fn emit(self: *PackedSink, value: anytype) void {
        @setEvalBranchQuota(1_000_000);
        const F = @TypeOf(value);
        if (F != PackedBase and F != PackedSecure) @compileError("packed sink requires a packed base or secure residual");
        if (self.values) |values| values[self.count] = liftFor(F, value);
        if (self.weighted_accumulator) |accumulator| {
            std.debug.assert(self.count < accumulator.powers.len);
            const power = PackedSecure.splat(accumulator.powers[accumulator.powers.len - 1 - self.count]);
            const weighted = if (self.scale) |scale| power.mul(mulBaseFor(F, scale, value)) else mulBaseFor(F, power, value);
            accumulator.accumulation = accumulator.accumulation.add(weighted);
        }
        self.count += 1;
    }
};
pub inline fn booleanFor(comptime F: type, out: *SinkFor(F), value: F) void {
    out.emit(value.mul(value.sub(F.one())));
}

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
