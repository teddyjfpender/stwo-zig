//! Owned internal work must not consume the caller's matrix needed for binding.
const std = @import("std");
const core = @import("stwo_core");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const G = @import("gkr_prover.zig").ForField(O);
const V = @import("gkr_verifier.zig").ForField(O);
const ML = @import("mle.zig");
const SC = @import("sumcheck.zig").ForField(O);
fn value(i: usize) O {
    return O.fromBase(M.fromCanonical(@intCast(i + 3))).add(O.basis());
}
fn inputsUnchanged(n: []const M, d: []const O) !void {
    for (n, d, 0..) |nv, dv, i| {
        try std.testing.expect(nv.eql(M.fromCanonical(@intCast(i % 3))));
        try std.testing.expect(dv.eql(value(i)));
    }
}
fn borrowLifecycle(a: std.mem.Allocator) !void {
    const ns = try a.alloc(M, 32);
    defer a.free(ns);
    const ds = try a.alloc(O, 32);
    defer a.free(ds);
    for (ns, ds, 0..) |*n, *d, i| {
        n.* = M.fromCanonical(@intCast(i % 3));
        d.* = value(i);
    }
    const layer = G.Layer{ .LogUpMultiplicities = .{ .numerators = try ML.MleFor(O, M).initOwned(ns), .denominators = try ML.MleFor(O, O).initOwned(ds) } };
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    var proof = G.proveBatch(a, &channel, &.{layer}) catch |err| {
        try inputsUnchanged(ns, ds);
        return err;
    };
    defer proof.deinit(a);
    try inputsUnchanged(ns, ds);
    var fresh = core.channel.raw_mod_m31.Om31Channel.init();
    var artifact = try V.partiallyVerifyBatch(a, &.{.LogUp}, &proof.proof, &fresh);
    defer artifact.deinit(a);
    const expected = [_]O{ try layer.LogUpMultiplicities.numerators.evalAtPoint(a, artifact.ood_point), try layer.LogUpMultiplicities.denominators.evalAtPoint(a, artifact.ood_point) };
    try @import("verifier_kernel.zig").verifyTerminalInputs(O, &artifact, &[_][]const O{&expected}, V.NativeChecks{});
}
test "owned GKR work preserves caller-owned matrices through success and every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, borrowLifecycle, .{});
}
fn eqLifetime(a: std.mem.Allocator) !void {
    var parent = try G.EqEvals.generate(a, &.{ value(7), value(11) });
    defer parent.deinit(a);
    const expected = parent.at(0);
    var fixed: G.GkrMultivariatePolyOracle = undefined;
    {
        const values = try a.alloc(O, 8);
        for (values, 0..) |*v, i| v.* = value(i);
        const layer = G.Layer{ .GrandProduct = try ML.MleFor(O, O).initOwned(values) };
        var original = layer.intoMultivariatePolyOwned(value(3), &parent);
        defer original.deinit(a);
        fixed = try original.fixFirstVariable(a, value(5));
    }
    defer fixed.deinit(a);
    try std.testing.expect(fixed.eq_evals.evals.evals.ptr == parent.evals.evals.ptr);
    try std.testing.expect(!fixed.eq_evals.owns_y and !fixed.eq_evals.evals.owns_evals);
    try std.testing.expect(fixed.eq_evals.at(0).eql(expected));
}
test "GKR fixed-variable transitions share a scoped immutable Eq owner" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, eqLifetime, .{});
}
fn ownedEarly(a: std.mem.Allocator) !void {
    const values = try a.alloc(O, 4);
    @memset(values, O.one());
    const oracles = a.alloc(ML.MleFor(O, O), 1) catch |err| {
        a.free(values);
        return err;
    };
    oracles[0] = try ML.MleFor(O, O).initOwned(values);
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    try std.testing.expectError(error.EmptyBatch, SC.proveBatchOwned(ML.MleFor(O, O), a, &.{}, oracles, O.one(), &channel));
}
test "owned sumcheck consumes every owner on malformed early return" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, ownedEarly, .{});
}
fn ownedValid(a: std.mem.Allocator) !void {
    const values = try a.alloc(O, 4);
    var claim = O.zero();
    for (values, 0..) |*v, i| {
        v.* = value(i);
        claim = claim.add(v.*);
    }
    const oracles = a.alloc(ML.MleFor(O, O), 1) catch |err| {
        a.free(values);
        return err;
    };
    oracles[0] = try ML.MleFor(O, O).initOwned(values);
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    var result = try SC.proveBatchOwned(ML.MleFor(O, O), a, &.{claim}, oracles, value(3), &channel);
    defer result.deinit(a);
    var fresh = core.channel.raw_mod_m31.Om31Channel.init();
    var checked = try SC.partiallyVerify(a, claim, &result.proof, &fresh);
    defer checked.deinit(a);
    try std.testing.expect(checked.claimed_eval.eql(result.constant_polys[0].evals[0]));
}
test "owned sumcheck valid proof releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, ownedValid, .{});
}
test {
    _ = @import("om31_test.zig");
}
