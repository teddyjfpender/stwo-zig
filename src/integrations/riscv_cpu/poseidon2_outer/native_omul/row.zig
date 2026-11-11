//! Concrete OM31 product authority over eight base coordinates. Six complete
//! QM31 Var ports connect all inputs/outputs to the existing authenticated bus.
const std = @import("std");
const Core = @import("stwo_core");
const M = Core.fields.m31.M31;
pub const MAIN = 24;
pub const FIXED = 9;
pub const INTER = 24;
pub const ARITHMETIC_ROOTS = 8;
pub const PORTS = 6;
pub const ROOTS = ARITHMETIC_ROOTS + PORTS / 2;
pub const IDS = 0;
pub const USES = 6;
pub const ENABLED = 8;
pub const Gate = struct { inputs: [4]u32, outputs: [2]u32 };
fn lift(comptime F: type, value: M) F {
    return if (F == M) value else F.fromBase(value);
}
fn cmul(comptime F: type, a: [2]F, b: [2]F) [2]F {
    return .{ a[0].mul(b[0]).sub(a[1].mul(b[1])), a[0].mul(b[1]).add(a[1].mul(b[0])) };
}
fn times2i(comptime F: type, a: [2]F) [2]F {
    return .{ a[0].add(a[0]).sub(a[1]), a[0].add(a[1].add(a[1])) };
}
fn qmul(comptime F: type, a: [4]F, b: [4]F) [4]F {
    const ac = cmul(F, a[0..2].*, b[0..2].*);
    const bd = times2i(F, cmul(F, a[2..4].*, b[2..4].*));
    const ad = cmul(F, a[0..2].*, b[2..4].*);
    const bc = cmul(F, a[2..4].*, b[0..2].*);
    return .{ ac[0].add(bd[0]), ac[1].add(bd[1]), ad[0].add(bc[0]), ad[1].add(bc[1]) };
}
fn timesU(comptime F: type, a: [4]F) [4]F {
    const low = times2i(F, a[2..4].*);
    return .{ low[0], low[1], a[0], a[1] };
}
pub fn productFor(comptime F: type, a: [8]F, b: [8]F) [8]F {
    const ac = qmul(F, a[0..4].*, b[0..4].*);
    const bd = timesU(F, qmul(F, a[4..8].*, b[4..8].*));
    const ad = qmul(F, a[0..4].*, b[4..8].*);
    const bc = qmul(F, a[4..8].*, b[0..4].*);
    var out: [8]F = undefined;
    for (0..4) |i| {
        out[i] = ac[i].add(bd[i]);
        out[4 + i] = ad[i].add(bc[i]);
    }
    return out;
}
pub fn evaluateFor(comptime F: type, main: *const [MAIN]F) [ARITHMETIC_ROOTS]F {
    const product = productFor(F, main[0..8].*, main[8..16].*);
    var roots: [ARITHMETIC_ROOTS]F = undefined;
    for (&roots, main[16..24], product) |*root, actual, expected| root.* = actual.sub(expected);
    return roots;
}
pub fn PortFor(comptime F: type) type {
    return struct { numerator: F, tuple: [6]F };
}
pub fn portsFor(comptime F: type, main: *const [MAIN]F, fixed: *const [FIXED]F) [PORTS]PortFor(F) {
    const tag = lift(F, M.fromCanonical(@import("stwo_circuit_frontend").common.component_list.GATE_RELATION_ID));
    var out: [PORTS]PortFor(F) = undefined;
    for (&out, 0..) |*port, i| port.* = .{ .numerator = if (i < 4) fixed[ENABLED] else lift(F, M.zero()).sub(fixed[USES + i - 4]), .tuple = .{ tag, fixed[IDS + i], main[4 * i], main[4 * i + 1], main[4 * i + 2], main[4 * i + 3] } };
    return out;
}
pub fn rootsFor(comptime F: type, main: *const [MAIN]F, fixed: *const [FIXED]F, current: *const [3]F, previous: F, z: F, powers: [6]F, shift: F) [ROOTS]F {
    var roots: [ROOTS]F = undefined;
    roots[0..ARITHMETIC_ROOTS].* = evaluateFor(F, main);
    const ports = portsFor(F, main, fixed);
    var prior = lift(F, M.zero());
    for (0..3) |i| {
        var d0 = lift(F, M.zero()).sub(z);
        var d1 = d0;
        for (ports[2 * i].tuple, ports[2 * i + 1].tuple, powers) |a, b, power| {
            d0 = d0.add(a.mul(power));
            d1 = d1.add(b.mul(power));
        }
        const numerator = ports[2 * i].numerator.mul(d1).add(ports[2 * i + 1].numerator.mul(d0));
        const delta = if (i == 2) current[i].sub(previous).add(shift).sub(prior) else current[i].sub(prior);
        roots[ARITHMETIC_ROOTS + i] = d0.mul(d1).mul(delta).sub(numerator);
        prior = current[i];
    }
    return roots;
}
/// Semantic matrix/port identity, independent of witness/prover implementation.
/// The native tower defines the coefficient tensor; qualification checks the
/// factored evaluator against that tensor and the same native arithmetic.
pub fn semanticIdentity() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("opstack/outer-native-om31-mul/r6-v1/8-quadratic/6-complete-QM-ports/3-paired-prefix/degree3");
    const O = Core.fields.om31.OM31;
    for (0..8) |i| for (0..8) |j| {
        var a: [8]M = @splat(M.zero());
        var b = a;
        a[i] = M.one();
        b[j] = M.one();
        for (O.fromM31Array(a).mul(O.fromM31Array(b)).toM31Array()) |coefficient| {
            var raw: [4]u8 = undefined;
            std.mem.writeInt(u32, &raw, coefficient.v, .little);
            hash.update(&raw);
        }
    };
    var tag: [4]u8 = undefined;
    std.mem.writeInt(u32, &tag, @import("stwo_circuit_frontend").common.component_list.GATE_RELATION_ID, .little);
    hash.update(&tag);
    return hash.finalResult();
}
pub fn fixedFor(gate: Gate, uses: []const u32) ![FIXED]M {
    var fixed: [FIXED]M = undefined;
    for (gate.inputs, 0..) |id, i| {
        if (id >= uses.len or id >= Core.fields.m31.Modulus) return error.InvalidNativeOmulAddress;
        fixed[i] = M.fromCanonical(id);
    }
    for (gate.outputs, 0..) |id, i| {
        if (id >= uses.len or id >= Core.fields.m31.Modulus or uses[id] >= Core.fields.m31.Modulus) return error.InvalidNativeOmulAddress;
        fixed[4 + i] = M.fromCanonical(id);
        fixed[USES + i] = M.fromCanonical(uses[id]);
    }
    fixed[ENABLED] = M.one();
    return fixed;
}
pub fn paddingFixed() [FIXED]M {
    return @splat(M.zero());
}
pub fn fill(a: Core.fields.om31.OM31, b: Core.fields.om31.OM31) [MAIN]M {
    var out: [MAIN]M = undefined;
    out[0..8].* = a.toM31Array();
    out[8..16].* = b.toM31Array();
    out[16..24].* = a.mul(b).toM31Array();
    return out;
}
fn allZero(comptime F: type, values: []const F) bool {
    for (values) |value| if (!value.isZero()) return false;
    return true;
}

test "OP R6 native OM31 row matches tower arithmetic and binds every output coordinate" {
    const O = Core.fields.om31.OM31;
    for (0..64) |seed| {
        var aa: [8]M = undefined;
        var bb: [8]M = undefined;
        for (&aa, &bb, 0..) |*a, *b, i| {
            a.* = M.fromCanonical(@intCast((seed * 193 + i * 991) % Core.fields.m31.Modulus));
            b.* = M.fromCanonical(@intCast((seed * 313 + i * 1117 + 1) % Core.fields.m31.Modulus));
        }
        const row = fill(O.fromM31Array(aa), O.fromM31Array(bb));
        try std.testing.expect(allZero(M, &evaluateFor(M, &row)));
        for (0..8) |i| {
            var forged = row;
            forged[16 + i] = forged[16 + i].add(M.one());
            try std.testing.expect(!allZero(M, &evaluateFor(M, &forged)));
        }
    }
    const pad: [MAIN]M = @splat(M.zero());
    try std.testing.expect(allZero(M, &evaluateFor(M, &pad)));
}
test "OP R6 native OM31 row Var tuples include all QM31 coordinates and source fanout" {
    var uses: [32]u32 = @splat(0);
    uses[12] = 3;
    uses[13] = 5;
    const fixed = try fixedFor(.{ .inputs = .{ 4, 5, 6, 7 }, .outputs = .{ 12, 13 } }, &uses);
    var main: [MAIN]M = undefined;
    for (&main, 0..) |*value, i| value.* = M.fromCanonical(@intCast(i + 1));
    const ports = portsFor(M, &main, &fixed);
    for (ports, 0..) |port, i| for (0..4) |j| try std.testing.expectEqual(main[4 * i + j].v, port.tuple[2 + j].v);
    try std.testing.expectEqual(M.fromCanonical(3).neg().v, ports[4].numerator.v);
    try std.testing.expectEqual(M.fromCanonical(5).neg().v, ports[5].numerator.v);
    for (portsFor(M, &main, &paddingFixed())) |port| try std.testing.expect(port.numerator.isZero());
}

test "OP R6 native OM31 complete row and paired LogUp remain degree3" {
    var values: [5][ROOTS]M = undefined;
    for (&values, 0..) |*roots, t| {
        const x = M.fromCanonical(@intCast(t));
        var main: [MAIN]M = undefined;
        var fixed: [FIXED]M = undefined;
        var current: [3]M = undefined;
        for (&main, 0..) |*v, i| v.* = M.fromCanonical(@intCast(i * 23 + 11)).add(x.mul(M.fromCanonical(@intCast(i * 7 + 5))));
        for (&fixed, 0..) |*v, i| v.* = M.fromCanonical(@intCast(i * 13 + 7)).add(x.mul(M.fromCanonical(@intCast(i * 3 + 2))));
        for (&current, 0..) |*v, i| v.* = M.fromCanonical(@intCast(i * 31 + 1)).add(x.mul(M.fromCanonical(@intCast(i * 5 + 2))));
        const previous = M.fromCanonical(73).add(x.mul(M.fromCanonical(19)));
        roots.* = rootsFor(M, &main, &fixed, &current, previous, M.fromCanonical(719), .{ M.one(), M.fromCanonical(11), M.fromCanonical(17), M.fromCanonical(23), M.fromCanonical(31), M.fromCanonical(37) }, M.fromCanonical(53));
    }
    var n: usize = 5;
    for (0..4) |_| {
        for (0..n - 1) |i| {
            for (0..ROOTS) |j| values[i][j] = values[i + 1][j].sub(values[i][j]);
        }
        n -= 1;
    }
    for (values[0]) |value| try std.testing.expect(value.isZero());
}
