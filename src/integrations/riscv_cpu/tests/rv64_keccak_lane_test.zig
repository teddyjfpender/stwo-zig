const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const V = A.evaluation;
const K = A.crypto.keccak;
const E = K.equations;
const L = K.layout;
const Q = V.Q;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
const Scalar = K.component.Scratch;
fn randomQ(rng: std.Random) Q {
    return Q.fromU32Unchecked(rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus);
}
fn fill(comptime F: type, rng: std.Random, destination: []F, scalar: []Scalar, comptime field: []const u8) void {
    for (destination, 0..) |*value, column| {
        var lanes: [V.LANES]Q = undefined;
        var base: [V.LANES]M = undefined;
        for (0..V.LANES) |lane| {
            lanes[lane] = if (F == V.PackedBase) Q.fromBase(M.fromU64(rng.int(u32))) else randomQ(rng);
            base[lane] = lanes[lane].c0.a;
            @field(scalar[lane], field)[column] = lanes[lane];
        }
        value.* = if (F == V.PackedBase) V.PackedBase.fromLanes(base) else V.PackedSecure.fromLanes(lanes);
    }
}
fn compare(comptime F: type) !void {
    return compareWithPolicy(F, .triple_v2);
}
pub fn compareWithPolicy(comptime F: type, policy: E.BatchPolicy) !void {
    var prng = std.Random.DefaultPrng.init(0x4b454343414b3136);
    const rng = prng.random();
    const scalar = try a.alloc(Scalar, V.LANES);
    defer a.free(scalar);
    const fixed = try a.create([L.FIXED]F);
    defer a.destroy(fixed);
    const main = try a.create([L.MAIN]F);
    defer a.destroy(main);
    const shifted = try a.create([4][L.STATE]F);
    defer a.destroy(shifted);
    const header = try a.create([3]F);
    defer a.destroy(header);
    const interaction = try a.create([L.BATCHES]V.PackedSecure);
    defer a.destroy(interaction);
    fill(F, rng, fixed, scalar, "fixed");
    fill(F, rng, main, scalar, "main");
    fill(F, rng, header, scalar, "previous_header");
    for (shifted, 0..) |*destination, j| for (destination, 0..) |*value, column| {
        var lanes: [V.LANES]Q = undefined;
        var base: [V.LANES]M = undefined;
        for (0..V.LANES) |lane| {
            lanes[lane] = if (F == V.PackedBase) Q.fromBase(M.fromU64(rng.int(u32))) else randomQ(rng);
            base[lane] = lanes[lane].c0.a;
            scalar[lane].shifted[j][column] = lanes[lane];
        }
        value.* = if (F == V.PackedBase) V.PackedBase.fromLanes(base) else V.PackedSecure.fromLanes(lanes);
    };
    for (interaction, 0..) |*value, column| {
        var lanes: [V.LANES]Q = undefined;
        for (0..V.LANES) |lane| {
            lanes[lane] = randomQ(rng);
            scalar[lane].interaction[column] = lanes[lane];
        }
        value.* = V.PackedSecure.fromLanes(lanes);
    }
    var previous: [V.LANES]Q = undefined;
    for (&previous) |*v| v.* = randomQ(rng);
    var ch: E.Challenges = undefined;
    inline for (.{ "chi", "xor5", "io" }) |field| {
        @field(ch, field).offset = randomQ(rng);
        for (&@field(ch, field).coefficients) |*v| v.* = randomQ(rng);
    }
    const claim = randomQ(rng);
    const output = try a.alloc(V.PackedSecure, policy.constraints());
    defer a.free(output);
    const expected = try a.alloc(Q, policy.constraints());
    defer a.free(expected);
    var sink = V.PackedSink{ .values = output };
    const row = E.RowFor(F){ .fixed = fixed, .main = main, .previous_header = header, .state_minus_two = &shifted[0], .state_minus_one = &shifted[1], .state_plus_one = &shifted[2], .state_plus_two = &shifted[3] };
    const public = E.Public{ .calls = 3, .first_id = core.fields.m31.Modulus - 3 };
    E.emitForPolicy(F, policy, row, interaction, V.PackedSecure.fromLanes(previous), claim, ch, public, &sink);
    try std.testing.expectEqual(policy.constraints(), sink.count);
    for (scalar, 0..) |*s, lane| {
        var oracle = V.Sink{ .values = expected };
        E.emitForPolicy(Q, policy, s.row(), &s.interaction, previous[lane], claim, ch, public, &oracle);
        try std.testing.expectEqual(oracle.count, sink.count);
        for (expected, output) |v, actual| try std.testing.expect(v.eql(actual.lane(lane)));
    }
    // Fixed/main values are deliberately arbitrary, including all phase selectors
    // and active flags; this also checks the full OODS polynomial, not a trace-only shortcut.
    inline for (.{ K.component.Kind.chi, K.component.Kind.xor5 }) |kind| {
        const c = K.component.Component{ .kind = kind, .log_size = if (kind == .chi) 13 else 10, .challenges = ch, .claim = claim };
        const tuple: [6]F = main[0..6].*;
        const actual = K.component.tableResidualFor(F, &c, &tuple, fixed[0], main[6], interaction[0], V.PackedSecure.fromLanes(previous));
        for (scalar, 0..) |*s, lane| {
            const scalar_tuple: [6]Q = s.main[0..6].*;
            const reference = K.component.tableResidual(&c, &scalar_tuple, s.fixed[0], s.main[6], s.interaction[0], previous[lane]);
            try std.testing.expect(reference.eql(actual.lane(lane)));
        }
    }
}
test "Keccak SIMD16 shared polynomial matches every residual for arbitrary base rows" {
    try compare(V.PackedBase);
}
test "Keccak SIMD16 retains every arbitrary extension OODS residual" {
    try compare(V.PackedSecure);
}
