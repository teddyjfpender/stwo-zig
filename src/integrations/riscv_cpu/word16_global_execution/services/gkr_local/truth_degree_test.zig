//! Degree checks exercise the ACTUAL joined role emitter, including strict local
//! inverses, joint prefix, original MAIN equations and pure global relations.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const Role = @import("truth_role.zig");
const T = @import("truth_fractions.zig");
const Manifest = @import("manifest.zig");
fn dense(seed: usize) O {
    var c: [8]M = undefined;
    for (&c, 0..) |*v, i| v.* = M.fromCanonical(@intCast((seed * 71 + i * 79 + 3) % 1000003));
    return O.fromM31Array(c);
}
const Samples = struct {
    point: M,
    pub fn get(self: @This(), tree: usize, col: usize, shift: i32) !O {
        const seed = tree * 100003 + col * 11 + @as(usize, @intCast(shift + 2));
        return dense(seed).add(dense(seed + 7919).mulM31(self.point));
    }
    pub fn last(self: @This()) !O {
        return dense(821).add(dense(541).mulM31(self.point));
    }
};
fn check(kind: Role.Kind, max_degree: usize) !void {
    var ch = core.channel.raw_mod_m31.Om31Channel.init();
    const local = T.ChallengesFor(O).draw(&ch);
    var shared: Manifest.Shared = undefined;
    shared.ram.offset = ch.drawSecureFelt();
    for (&shared.ram.coefficients) |*v| v.* = ch.drawSecureFelt();
    shared.kio = A.crypto.keccak.equations.IoFor(O).draw(&ch);
    shared.wire = A.crypto.secp256k1.equations.WireFor(O).draw(&ch);
    const role = Role.Component{ .kind = kind, .log_size = 5, .calls = 0, .first_id = 1, .program = if (kind == .product or kind == .linear) A.crypto.secp256k1.program.get(.add) else null, .byte_policy = .canonical_inputs, .local = local, .shared = shared, .claim = dense(31), .global_claim = dense(41), .split = if (kind == .keccak) 2 else 1 };
    const count = role.nConstraints();
    const values = try std.testing.allocator.alloc(O, (max_degree + 2) * count);
    defer std.testing.allocator.free(values);
    for (0..max_degree + 2) |t| {
        var sink = A.evaluation.SinkFor(O){ .values = values[t * count ..][0..count] };
        try role.emitFor(O, Samples{ .point = M.fromCanonical(@intCast(t)) }, &sink);
        try std.testing.expectEqual(count, sink.count);
    }
    var saw_top = false;
    for (0..count) |c| {
        var difference: [7]O = undefined;
        for (0..max_degree + 2) |t| difference[t] = values[t * count + c];
        for (0..max_degree + 1) |d| {
            for (0..max_degree + 1 - d) |t| difference[t] = difference[t + 1].sub(difference[t]);
            if (d + 1 == max_degree and !difference[0].isZero()) saw_top = true;
        }
        try std.testing.expect(difference[0].isZero());
    }
    try std.testing.expect(saw_top);
}
test "joined Keccak classic strict-triple and pure-global authority is at most degree5 and uses degree5" {
    try check(.keccak, 5);
}
test "joined secp classic pair and pure-global authority remains degree3" {
    try check(.product, 3);
    try check(.linear, 3);
}
