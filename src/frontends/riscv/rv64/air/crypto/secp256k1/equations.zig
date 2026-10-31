//! One QM31 polynomial authority; direct modular equations are shared unchanged.
const Eval = @import("../../evaluation.zig");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
pub const Q = core.fields.qm31.QM31;
const L = @import("layout.zig");
const P = L.P;
pub const Wire = struct {
    offset: Q,
    coefficients: [L.WIRE_ARITY]Q,
    pub fn draw(channel: anytype) Wire {
        channel.mixU32s(&.{0x53575031});
        var out: Wire = undefined;
        out.offset = channel.drawSecureFelt();
        for (&out.coefficients) |*v| v.* = channel.drawSecureFelt();
        return out;
    }
    pub fn denominator(self: Wire, tuple: *const [L.WIRE_ARITY]Q) Q {
        var out = self.offset;
        for (tuple, self.coefficients) |v, c| out = out.sub(v.mul(c));
        return out;
    }
};
pub const Challenges = struct {
    polynomial: Q,
    bytes: Q,
    wire: Wire,
    pub fn draw(channel: anytype) Challenges {
        return .{ .polynomial = channel.drawSecureFelt(), .bytes = channel.drawSecureFelt(), .wire = Wire.draw(channel) };
    }
};
pub const Public = struct { calls: u32, first_id: u32 = 1 };
pub const Row = RowFor(Q);
pub fn RowFor(comptime F: type) type {
    return struct { fixed: *const [L.FIXED]F, main: []const F, previous_active: F = .zero(), previous_id: F = .zero() };
}
fn q(v: u32) Q {
    return Q.fromBase(M.fromCanonical(v));
}
fn DirectSinkFor(comptime F: type) type {
    return struct {
        sink: *Eval.SinkFor(F),
        pub fn add(self: @This(), value: anytype, degree: u8) void {
            _ = degree;
            self.sink.emit(value);
        }
    };
}
pub fn emit(kind: L.Kind, program: *const P.Program, row: Row, current: []const Q, previous_final: Q, claim: Q, ch: Challenges, public: Public, sink: *Eval.Sink) void {
    emitGeneric(Q, kind, program, row, current, previous_final, claim, ch, public, sink);
}
pub fn emitGeneric(comptime F: type, kind: L.Kind, program: *const P.Program, row: RowFor(F), current: []const Eval.SecureFor(F), previous_final: Eval.SecureFor(F), claim: Q, ch: Challenges, public: Public, sink: *Eval.SinkFor(F)) void {
    const active = row.main[0];
    const id = row.main[L.base(kind)];
    const f = row.fixed;
    const target = Eval.qFor(F, public.first_id + public.calls - 1);
    if (kind == .product) L.mul.evaluateGeneric(F, row.main[0..L.mul.Layout.main_columns], P.field.base_modulus, Eval.splatFor(F, ch.polynomial), DirectSinkFor(F){ .sink = sink }) else L.linear.evaluateGeneric(F, row.main[0..L.linear.Layout.main_columns], P.field.base_modulus, DirectSinkFor(F){ .sink = sink });
    sink.emit(F.one().sub(f[L.COMPLETE]).mul(active));
    sink.emit(f[L.FIRST].mul(active.sub(Eval.qFor(F, @intFromBool(public.calls != 0)))));
    sink.emit(F.one().sub(f[L.PHASE_FIRST]).mul(active.sub(row.previous_active)));
    sink.emit(F.one().sub(f[L.PHASE_FIRST]).mul(id.sub(row.previous_id)));
    sink.emit(f[L.PHASE_FIRST].sub(f[L.FIRST]).mul(F.one().sub(row.previous_active)).mul(active));
    sink.emit(f[L.PHASE_FIRST].sub(f[L.FIRST]).mul(row.previous_active.sub(active)).mul(row.previous_id.sub(target)));
    sink.emit(active.mul(id.sub(Eval.qFor(F, public.first_id)).sub(f[L.CALL_INDEX])));
    sink.emit(F.one().sub(active).mul(id));
    for (row.main[1..L.base(kind)]) |v| sink.emit(F.one().sub(active).mul(v));
    const rhs = if (kind == .product) L.mul.Layout.rhs else L.linear.Layout.rhs;
    for (0..32) |i| {
        const constant = (if (i == 0) f[L.RHS_SMALL] else F.zero()).add(f[L.REDUCE].mul(Eval.qFor(F, P.field.base_modulus.bytes[i])));
        sink.emit(active.mul(F.one().sub(f[L.RHS_WIRE])).mul(row.main[rhs + i].sub(constant)));
    }
    if (kind == .linear) {
        sink.emit(row.main[L.linear.Layout.selector_add].sub(active.mul(f[L.ADD])));
        sink.emit(row.main[L.linear.Layout.selector_subtract].sub(active.mul(f[L.SUB])));
        sink.emit(row.main[L.linear.Layout.selector_reduce_once].sub(active.mul(f[L.REDUCE])));
    }
    const S = Eval.SecureFor(F);
    for (0..L.batches(kind)) |batch| {
        var denominators: [3]S = @splat(S.one());
        var coefficients: [3]F = @splat(F.zero());
        if (batch + 1 == L.batches(kind)) {
            for (0..3) |event| {
                denominators[event] = Eval.denominatorFor(F, ch.wire.offset, &ch.wire.coefficients, &wireTupleFor(F, kind, program, row, event), true);
                coefficients[event] = wireCoefficientFor(F, row, event);
            }
        } else for (0..3) |j| {
            const index = 3 * batch + j;
            if (index < L.byteCount(kind)) {
                denominators[j] = Eval.splatFor(F, ch.bytes).sub(Eval.liftFor(F, byteFor(F, kind, row.main, index)));
                coefficients[j] = F.one();
            }
        }
        const denominator = denominators[0].mul(denominators[1]).mul(denominators[2]);
        const numerator = Eval.mulBaseFor(F, denominators[1].mul(denominators[2]), coefficients[0]).add(Eval.mulBaseFor(F, denominators[0].mul(denominators[2]), coefficients[1])).add(Eval.mulBaseFor(F, denominators[0].mul(denominators[1]), coefficients[2]));
        const delta = current[batch].sub(if (batch == 0) previous_final else current[batch - 1]).add(if (batch == 0) Eval.mulBaseFor(F, Eval.splatFor(F, claim), f[L.FIRST]) else S.zero());
        sink.emit(delta.mul(denominator).sub(numerator));
    }
}
pub fn byte(kind: L.Kind, main: []const Q, index: usize) Q {
    return byteFor(Q, kind, main, index);
}
pub fn byteFor(comptime F: type, kind: L.Kind, main: []const F, index: usize) F {
    return if (kind == .product) main[L.mul.Layout.first_byte + index] else if (index < 96) main[L.linear.Layout.lhs + index] else main[L.linear.Layout.canonical_sum + index - 96];
}
pub fn wireCoefficient(row: Row, event: usize) Q {
    return wireCoefficientFor(Q, row, event);
}
pub fn wireCoefficientFor(comptime F: type, row: RowFor(F), event: usize) F {
    return row.main[0].mul(switch (event) {
        0 => row.fixed[L.LHS_WIRE].neg(),
        1 => row.fixed[L.RHS_WIRE].neg(),
        2 => row.fixed[L.USES],
        else => unreachable,
    });
}
pub fn wireTuple(kind: L.Kind, program: *const P.Program, row: Row, event: usize) [L.WIRE_ARITY]Q {
    return wireTupleFor(Q, kind, program, row, event);
}
pub fn wireTupleFor(comptime F: type, kind: L.Kind, program: *const P.Program, row: RowFor(F), event: usize) [L.WIRE_ARITY]F {
    var out: [L.WIRE_ARITY]F = undefined;
    out[0] = Eval.qFor(F, @intFromEnum(program.kind));
    out[1] = row.main[L.base(kind)];
    out[2] = row.fixed[
        switch (event) {
            0 => L.LHS_ID,
            1 => L.RHS_ID,
            2 => L.RESULT_ID,
            else => unreachable,
        }
    ];
    const offset = if (kind == .product) switch (event) {
        0 => L.mul.Layout.lhs,
        1 => L.mul.Layout.rhs,
        else => L.mul.Layout.result,
    } else switch (event) {
        0 => L.linear.Layout.lhs,
        1 => L.linear.Layout.rhs,
        else => L.linear.Layout.result,
    };
    @memcpy(out[3..], row.main[offset..][0..32]);
    return out;
}
pub fn externalTuple(program: *const P.Program, id: u32, wire: u8, value: u256) [L.WIRE_ARITY]Q {
    var out: [L.WIRE_ARITY]Q = undefined;
    out[0] = q(@intFromEnum(program.kind));
    out[1] = q(id);
    out[2] = q(wire);
    const bytes = P.bytes(value);
    for (out[3..], bytes) |*v, b| v.* = q(b);
    return out;
}
