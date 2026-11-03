const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const C = @import("common.zig");
const Public = @import("frame.zig");
const G = @import("../../logup_gkr/om31_circuit_verifier.zig");
const Child = @import("cpu_child.zig");
const Native = @import("../../word16_global_execution/services/gkr_local/child.zig");
const Frame = @import("../../word16_global_execution/services/gkr_local/frame.zig");
const Receipt = @import("../../word16_global_execution/services/gkr_local/receipt.zig");
const Challenges = @import("../../word16_global_execution/services/gkr_local/challenges.zig");
const GP = engine.lookups.gkr_prover.ForField(C.O);
const a = std.testing.allocator;
const scope = Receipt.Scope{ .statement = @splat(3), .fixed = @splat(7), .main = @splat(11), .ordinal = 17 };
const instances = [_]Frame.Instance{.{ .origin = .{ .core = .alu }, .row_log = 5, .terms = 1, .fixed_offset = 2, .main_offset = 7 }};
const Fixture = struct {
    result: GP.ProveBatchResult,
    eta: C.O,
    receipt: [32]u8,
    fn init() !@This() {
        var channel = Native.begin(scope, &instances);
        _ = Challenges.For(C.O).drawForInstances(&channel, &instances);
        const zeroes = [_]C.O{C.O.zero()} ** 32;
        var ds: [32]C.O = undefined;
        for (&ds, 0..) |*d, i| d.* = C.O.fromBase(core.fields.m31.M31.fromCanonical(@intCast(107 + i * 13)));
        const layers = [_]GP.Layer{.{ .LogUpGeneric = .{ .numerators = .{ .evals = @constCast(&zeroes), .owns_evals = false }, .denominators = .{ .evals = &ds, .owns_evals = false } } }};
        const result = try GP.proveBatch(a, &channel, &layers);
        return .{ .result = result, .eta = channel.drawSecureFelt(), .receipt = try Receipt.digest(scope, &instances, &result.proof, result.artifact.claims_to_verify_by_instance) };
    }
    fn deinit(self: *@This()) void {
        self.result.deinit(a);
    }
};
fn run(fixture: *const Fixture, corrupt_receipt: bool, mutate: bool) !bool {
    var ctx = try C.Context.init(a, 0);
    defer ctx.deinit();
    C.lane.begin(&ctx);
    var active = true;
    defer if (active) C.lane.finish() catch {};
    var frame = Public.Frame.init(&ctx);
    const public = Child.Scope{ .statement = try frame.guessDigest(scope.statement), .fixed = try frame.guessDigest(scope.fixed), .main = try frame.guessDigest(scope.main), .ordinal = (try frame.guessU32(scope.ordinal)).word };
    var proof = try G.wireProof(&ctx, &fixture.result.proof);
    if (mutate) proof.layer_masks_by_instance[0][0].columns[0][0] = proof.layer_masks_by_instance[0][0].columns[0][0].add(C.F.one());
    var pending = try Child.verify(&ctx, public, &instances, &proof);
    defer pending.artifact.deinit(a);
    var expected_receipt = fixture.receipt;
    if (corrupt_receipt) expected_receipt[0] ^= 1;
    try Public.requireDigest(&ctx, pending.receipt, expected_receipt);
    try C.eq(&ctx, pending.eta, try C.F.guess(&ctx, fixture.eta));
    for (pending.artifact.ood_point, fixture.result.artifact.ood_point) |wire, expected| try C.eq(&ctx, wire, try C.F.guess(&ctx, expected));
    try C.lane.finish();
    active = false;
    try ctx.finalize(false);
    return ctx.isCircuitValid();
}
test "CPU leaf checked GKR child has byte-exact canonical unaligned receipt and eta" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try std.testing.expect(try run(&fixture, false, false));
}
test "CPU leaf checked GKR receipt rejects changed receipt and numerical proof" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const mutations = [_][2]bool{ .{ true, false }, .{ false, true } };
    for (mutations) |m| {
        const valid = run(&fixture, m[0], m[1]) catch |err| switch (err) {
            error.EqFailedOnEval => false,
            else => return err,
        };
        try std.testing.expect(!valid);
    }
}
