//! Closed expression seam only: native-conforming terminal projections accepting
//! symbolic/external transcript parameters. No circuit child/Statement admission.
//! Arithmetic constraints remain the original G.fixture.emit; this file changes
//! neither its source nor the qualified native projection/transport.
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const C = A.crypto.bn254_pairing_mac12.fixture;
const Mac = A.crypto.bn254_mac12.source;
// Private Hint95 layout is not exported by the frontend. Mirror only these
// projection offsets; native conformance tests pin them to the original emitter.
const Hint = struct {
    const BYTE_QUERIES = 64;
    const ACTIVE = 0;
};
comptime {
    if (C.mainWidth(.hints) != 95 or C.fixedWidth(.hints) != 3) @compileError("Hint95 projection layout changed");
}
const N = @import("../op_pairing_mac12/native.zig");
pub const Instance = N.Instance;
pub fn ParamsFor(comptime Lane: type) type {
    return struct {
        instance: Instance,
        weights: []const Lane,
        beta: Lane,
        ssa: struct { offset: Lane, coefficients: [35]Lane },
        eta: Lane,
        target: Lane,
    };
}
pub fn ResultFor(comptime F: type) type {
    return struct { numerator: E.SecureFor(F), denominator: E.SecureFor(F) };
}
/// Metadata is receiver/source authority, not a proof-provided free geometry.
/// Restrict this prototype to the existing exact six-instance roster.
pub fn validate(instance: Instance) !void {
    for (N.INSTANCES) |known| if (known.family == instance.family and known.role == instance.role and known.row_log == instance.row_log and known.lane_log == instance.lane_log) return;
    return error.PairingR7ProjectionShape;
}
fn dummy(comptime F: type) struct { F, E.SecureFor(F) } {
    return .{ F.zero(), E.SecureFor(F).one() };
}
/// SAME row-major lane selection and dummy N=0,D=1 as the qualified native
/// expression. Challenge/weight values are lane parameters, never native Q data.
pub fn fraction(comptime F: type, v: anytype, p: *const ParamsFor(E.ConstFor(F)), lane: usize) !struct { F, E.SecureFor(F) } {
    try validate(p.instance);
    if (lane >= p.instance.lanes()) return error.PairingR7ProjectionLane;
    if (p.instance.family == .bytes) {
        const beta = E.splatFor(F, p.beta);
        return switch (p.instance.role) {
            .arithmetic => if (lane >= Mac.BYTE_QUERIES) dummy(F) else .{ v.main(Mac.ACTIVE), beta.sub(E.liftFor(F, Mac.byteQuery(F, v, lane))) },
            .hints => if (lane >= Hint.BYTE_QUERIES) dummy(F) else .{ v.fixed(Hint.ACTIVE), beta.sub(E.liftFor(F, v.main(lane))) },
            .table => if (lane != 0) dummy(F) else .{ v.main(0).neg(), beta.sub(E.liftFor(F, v.fixed(0))) },
            else => return error.PairingR7ProjectionShape,
        };
    }
    var tuple: [35]F = undefined;
    tuple[0] = E.qFor(F, C.KIND);
    tuple[1] = F.one();
    var weight: F = undefined;
    switch (p.instance.role) {
        .arithmetic => {
            if (lane > 25) return dummy(F);
            if (lane < 25) {
                tuple[2] = v.fixed(Mac.INPUT_ID + lane);
                weight = v.main(Mac.ACTIVE).neg();
                for (0..32) |i| tuple[3 + i] = v.main(Mac.INPUT + 32 * lane + i);
            } else {
                tuple[2] = v.fixed(Mac.WRITER_ID);
                weight = v.main(Mac.ACTIVE).mul(v.fixed(Mac.FANOUT));
                for (0..32) |i| tuple[3 + i] = v.main(Mac.OUTPUT + i);
            }
        },
        .hints => {
            if (lane != 0) return dummy(F);
            tuple[2] = v.fixed(1);
            for (0..32) |i| tuple[3 + i] = v.main(i);
            weight = v.fixed(0).mul(v.fixed(2));
        },
        .frontier => {
            if (lane != 0) return dummy(F);
            tuple[2] = v.fixed(1);
            for (0..32) |i| tuple[3 + i] = v.main(1 + i);
            weight = v.main(0).mul(v.fixed(2));
        },
        else => return error.PairingR7ProjectionShape,
    }
    return .{ weight, E.denominatorFor(F, p.ssa.offset, &p.ssa.coefficients, &tuple, true) };
}
pub fn evaluate(comptime F: type, v: anytype, p: *const ParamsFor(E.ConstFor(F))) !ResultFor(F) {
    try validate(p.instance);
    if (p.weights.len != p.instance.lanes()) return error.PairingR7ProjectionWeights;
    var out = ResultFor(F){ .numerator = E.SecureFor(F).zero(), .denominator = E.SecureFor(F).zero() };
    for (p.weights, 0..) |weight, lane| {
        const pair = try fraction(F, v, p, lane);
        const w = E.splatFor(F, weight);
        out.numerator = out.numerator.add(E.mulBaseFor(F, w, pair[0]));
        out.denominator = out.denominator.add(w.mul(pair[1]));
    }
    return out;
}
/// The existing binding's local row residual before the prefix recurrence:
/// Eq(row) * (N(row) + eta * D(row)) - target. Eq/masks must come from the
/// independently verified source point; this helper does not manufacture them.
pub fn bindingResidual(comptime F: type, out: ResultFor(F), p: *const ParamsFor(E.ConstFor(F)), eq: E.SecureFor(F)) E.SecureFor(F) {
    return eq.mul(out.numerator.add(E.splatFor(F, p.eta).mul(out.denominator))).sub(E.splatFor(F, p.target));
}
