//! One QM31 polynomial authority; direct modular equations are shared unchanged.
const Eval = @import("../../evaluation.zig");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
pub const Q = core.fields.qm31.QM31;
const L = @import("layout.zig");
const P = L.P;
pub fn WireFor(comptime C: type) type {
    return struct {
        offset: C,
        coefficients: [L.WIRE_ARITY]C,
        pub fn draw(channel: anytype) @This() {
            channel.mixU32s(&.{0x53575031});
            var out: @This() = undefined;
            out.offset = channel.drawSecureFelt();
            for (&out.coefficients) |*v| v.* = channel.drawSecureFelt();
            return out;
        }
        pub fn denominatorBase(self: @This(), tuple: *const [L.WIRE_ARITY]M) C {
            var out = self.offset;
            for (tuple, self.coefficients) |value, coefficient| out = out.sub(coefficient.mulM31(value));
            return out;
        }
        pub fn denominator(self: @This(), tuple: *const [L.WIRE_ARITY]C) C {
            var out = self.offset;
            for (tuple, self.coefficients) |v, c| out = out.sub(v.mul(c));
            return out;
        }
    };
}
pub const Wire = WireFor(Q);
/// Modular-arithmetic challenges over constant lane C (QM31 natively).
pub fn ChallengesFor(comptime C: type) type {
    return struct {
        polynomial: C,
        bytes: C,
        wire: WireFor(C),
        pub fn draw(channel: anytype) @This() {
            return .{ .polynomial = channel.drawSecureFelt(), .bytes = channel.drawSecureFelt(), .wire = WireFor(C).draw(channel) };
        }
    };
}
pub const Challenges = ChallengesFor(Q);
pub const Public = Eval.CallSpanFor(Q);
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
pub fn emitGeneric(comptime F: type, kind: L.Kind, program: *const P.Program, row: RowFor(F), current: []const Eval.SecureFor(F), previous_final: Eval.SecureFor(F), claim: Eval.ConstFor(F), ch: ChallengesFor(Eval.ConstFor(F)), public: Eval.CallSpanFor(Eval.ConstFor(F)), sink: *Eval.SinkFor(F)) void {
    return emitGenericForPolicy(F, kind, .local, program, row, current, previous_final, claim, ch, public, sink);
}
/// Original MAIN arithmetic and phase/call policy, independent of lookup
/// storage. BYTE GKR and global Wire closure remain mandatory obligations.
pub fn emitMainFor(comptime F: type, kind: L.Kind, row: RowFor(F), polynomial: Eval.ConstFor(F), public: Eval.CallSpanFor(Eval.ConstFor(F)), sink: *Eval.SinkFor(F)) void {
    const active = row.main[0];
    const id = row.main[L.base(kind)];
    const f = row.fixed;
    const target = Eval.lastIdFor(F, public);
    if (kind == .product) L.mul.evaluateGeneric(F, row.main[0..L.mul.Layout.main_columns], P.field.base_modulus, Eval.splatFor(F, polynomial), DirectSinkFor(F){ .sink = sink }) else L.linear.evaluateGeneric(F, row.main[0..L.linear.Layout.main_columns], P.field.base_modulus, DirectSinkFor(F){ .sink = sink });
    sink.emit(F.one().sub(f[L.COMPLETE]).mul(active));
    sink.emit(f[L.FIRST].mul(active.sub(Eval.nonemptyFor(F, public))));
    sink.emit(F.one().sub(f[L.PHASE_FIRST]).mul(active.sub(row.previous_active)));
    sink.emit(F.one().sub(f[L.PHASE_FIRST]).mul(id.sub(row.previous_id)));
    sink.emit(f[L.PHASE_FIRST].sub(f[L.FIRST]).mul(F.one().sub(row.previous_active)).mul(active));
    sink.emit(f[L.PHASE_FIRST].sub(f[L.FIRST]).mul(row.previous_active.sub(active)).mul(row.previous_id.sub(target)));
    sink.emit(active.mul(id.sub(Eval.firstIdFor(F, public)).sub(f[L.CALL_INDEX])));
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
}
pub fn emitGenericForPolicy(comptime F: type, kind: L.Kind, policy: L.BytePolicy, program: *const P.Program, row: RowFor(F), current: []const Eval.SecureFor(F), previous_final: Eval.SecureFor(F), claim: Eval.ConstFor(F), ch: ChallengesFor(Eval.ConstFor(F)), public: Eval.CallSpanFor(Eval.ConstFor(F)), sink: *Eval.SinkFor(F)) void {
    emitMainFor(F, kind, row, ch.polynomial, public, sink);
    const f = row.fixed;
    const S = Eval.SecureFor(F);
    for (0..L.batchesFor(kind, policy)) |batch| {
        var denominators: [3]S = @splat(S.one());
        var coefficients: [3]F = @splat(F.zero());
        if (batch + 1 == L.batchesFor(kind, policy)) {
            for (0..3) |event| {
                denominators[event] = Eval.denominatorFor(F, ch.wire.offset, &ch.wire.coefficients, &wireTupleFor(F, kind, program, row, event), true);
                coefficients[event] = wireCoefficientFor(F, row, event);
            }
        } else for (0..3) |j| {
            const index = 3 * batch + j;
            if (index < L.byteCountFor(kind, policy)) {
                denominators[j] = Eval.splatFor(F, ch.bytes).sub(Eval.liftFor(F, byteForPolicy(F, kind, policy, row.main, index)));
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
    return byteForPolicy(F, kind, .local, main, index);
}
pub fn byteForPolicy(comptime F: type, kind: L.Kind, policy: L.BytePolicy, main: []const F, index: usize) F {
    return main[L.byteColumnFor(kind, policy, index)];
}
pub fn wireCoefficient(row: Row, event: usize) Q {
    return wireCoefficientFor(Q, row, event);
}
fn MainCells(comptime F: type) type {
    return struct {
        values: []const F,
        pub inline fn at(self: @This(), index: usize) F {
            return self.values[index];
        }
    };
}
pub fn wireCoefficientFor(comptime F: type, row: RowFor(F), event: usize) F {
    return wireCoefficientAccessors(F, MainCells(F){ .values = row.main }, row.fixed, event);
}
pub fn wireCoefficientAccessors(comptime F: type, main: anytype, fixed: []const F, event: usize) F {
    return main.at(0).mul(switch (event) {
        0 => fixed[L.LHS_WIRE].neg(),
        1 => fixed[L.RHS_WIRE].neg(),
        2 => fixed[L.USES],
        else => unreachable,
    });
}
pub fn wireTuple(kind: L.Kind, program: *const P.Program, row: Row, event: usize) [L.WIRE_ARITY]Q {
    return wireTupleFor(Q, kind, program, row, event);
}
pub fn wireTupleFor(comptime F: type, kind: L.Kind, program: *const P.Program, row: RowFor(F), event: usize) [L.WIRE_ARITY]F {
    return wireTupleAccessors(F, kind, program, MainCells(F){ .values = row.main }, row.fixed, event);
}
pub fn wireTupleAccessors(comptime F: type, kind: L.Kind, program: *const P.Program, main: anytype, fixed: []const F, event: usize) [L.WIRE_ARITY]F {
    var out: [L.WIRE_ARITY]F = undefined;
    out[0] = if (F == M) M.fromCanonical(@intFromEnum(program.kind)) else Eval.qFor(F, @intFromEnum(program.kind));
    out[1] = main.at(L.base(kind));
    out[2] = fixed[
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
    for (out[3..], 0..) |*value, i| value.* = main.at(offset + i);
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
