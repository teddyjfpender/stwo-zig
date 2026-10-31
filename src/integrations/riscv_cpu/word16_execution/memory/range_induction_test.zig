//! Algebraic counterexamples isolate exactly which closure/range anchors the
//! reduced LS encoding requires. This is not an accepting open LS verifier.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const X = A.memory.load_store_v2;
const V = A.memory.load_store_v1;
const R = A.memory.closed_ram;
const E = A.evaluation;
const M = X.types.M;
const Q = X.types.Q;
const p = core.fields.m31.Modulus;
fn row(event: X.native.Event) [79]Q {
    const m = X.native.row(event);
    var q: [79]Q = undefined;
    for (&q, m) |*v, x| v.* = Q.fromBase(x);
    return q;
}
fn local(m: *const [79]Q) !void {
    const fixed = [_]Q{ Q.zero(), Q.one(), Q.zero() };
    const previous: [79]Q = @splat(Q.zero());
    var values: [300]Q = undefined;
    var out = E.Sink{ .values = &values };
    V.equations.emitLocalFor(Q, &fixed, m, &previous, 1, &out);
    for (values[0..out.count], 0..) |v, index| if (!v.isZero()) {
        std.debug.print("nonzero LS local residual {d}\n", .{index});
        return error.NonzeroLocalResidual;
    };
    try std.testing.expect(m[3].sub(m[12]).sub(m[13].mul(E.q(65536))).isZero());
}
fn canonicalKept(m: *const [79]Q) bool {
    for (X.layout.U16) |c| if (m[c].tryIntoM31()) |v| {
        if (v.v >= 65536) return false;
    } else |_| return false;
    for (X.layout.U8) |c| if (m[c].tryIntoM31()) |v| {
        if (v.v >= 256) return false;
    } else |_| return false;
    return true;
}
fn state() R.types.State {
    return .{ .value = 0x8070605040302010, .rights = 3 };
}
fn store() X.native.Event {
    const before = state();
    var after = before;
    after.value = (before.value & ~@as(u64, 255)) | 0x12;
    after.epoch = 1;
    after.tick = 4;
    return .{ .opcode = .SB, .a = 0x1000, .immediate = 0, .b = 0x0000000100010012, .epoch = 1, .tick = 4, .before = before, .after = after };
}
test "removed upper store B ranges require full OWNER19 binding even when every local residual vanishes" {
    const good = row(store());
    try local(&good);
    var forged = good;
    forged[37] = forged[37].add(E.q(65536));
    forged[38] = forged[38].sub(Q.one());
    try local(&forged);
    try std.testing.expect(canonicalKept(&forged));
    const before = X.equations.ownerTuple(Q, &good);
    const after = X.equations.ownerTuple(Q, &forged);
    try std.testing.expect(!before[10].eql(after[10]));
    try std.testing.expect(!before[11].eql(after[11]));
}
test "unranged before clock aliases are locally possible but change the physical RAM predecessor" {
    var event = store();
    event.before.epoch = 1;
    var good = row(event);
    try local(&good);
    const token = R.equations.ramTuple(Q, .transition, good[0..28], false);
    good[10] = E.q(p - 1);
    good[25] = E.q(4);
    try local(&good);
    try std.testing.expect(canonicalKept(&good));
    const forged = R.equations.ramTuple(Q, .transition, good[0..28], false);
    try std.testing.expect(!token[6].eql(forged[6]));
    // Every possible producer retains a canonical low-clock limb, so this
    // token cannot close against a producer merely by changing a local gap.
    try std.testing.expect((try good[10].tryIntoM31()).v >= 65536);
}
test "retained gap queries reject modular future epoch and reversed tick counterexamples" {
    var cross = row(store());
    cross[8] = E.q(2);
    cross[24] = E.q(p - 2);
    try local(&cross);
    try std.testing.expect(!canonicalKept(&cross));
    var event = store();
    event.before.epoch = 1;
    var tick = row(event);
    tick[10] = E.q(8);
    tick[25] = E.q(p - 5);
    try local(&tick);
    try std.testing.expect(!canonicalKept(&tick));
    tick[25] = E.q(65531);
    tick[26] = E.q(p - 1);
    tick[27] = Q.one();
    try local(&tick);
    try std.testing.expect(!canonicalKept(&tick));
}
test "retained RAM after and load C write ranges break the joint noncanonical read alias cycle" {
    const before = R.types.State{ .value = 65536, .rights = 3 };
    var after = before;
    after.epoch = 1;
    after.tick = 4;
    var m = row(.{ .opcode = .LD, .a = 0x1000, .immediate = 0, .c = before.value, .epoch = 1, .tick = 4, .before = before, .after = after });
    try local(&m);
    for ([_]usize{ 14, 18, 40 }) |column| {
        m[column] = m[column].add(E.q(65536));
        m[column + 1] = m[column + 1].sub(Q.one());
    }
    try local(&m);
    try std.testing.expect(!canonicalKept(&m));
}
test "removed address ranges require canonical INIT ancestry rather than local effective address equations" {
    var event = store();
    event.a = 65535;
    event.immediate = 1;
    var m = row(event);
    try local(&m);
    m[75] = Q.zero();
    m[44] = E.q(65536);
    m[45] = Q.zero();
    m[4] = E.q(65536);
    m[5] = Q.zero();
    m[68] = E.q(8192);
    try local(&m);
    try std.testing.expect(canonicalKept(&m));
    try std.testing.expect((try m[4].tryIntoM31()).v >= 65536);
    // OWNER is unchanged: only the independently anchored RAM path excludes it.
    const original = row(event);
    try std.testing.expectEqualDeep(X.equations.ownerTuple(Q, &original), X.equations.ownerTuple(Q, &m));
}

test "removed base and immediate limb ranges need canonical REG and immutable ROM OWNER anchors" {
    const good = row(store());
    for ([_]usize{ V.layout.a, V.layout.immediate }) |start| {
        var forged = good;
        forged[start] = forged[start].add(E.q(65536));
        forged[start + 1] = forged[start + 1].sub(Q.one());
        forged[V.layout.address_carries] = Q.one();
        try local(&forged);
        try std.testing.expect(canonicalKept(&forged));
        const expected = X.equations.ownerTuple(Q, &good);
        const actual = X.equations.ownerTuple(Q, &forged);
        try std.testing.expect(!expected[1 + start - V.layout.a].eql(actual[1 + start - V.layout.a]));
    }
}
