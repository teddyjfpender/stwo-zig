//! Actual native proof suite admission; no arbitrary supplied challenge knobs.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const wire = @import("stwo_proof_wire");
const Mat = @import("setup.zig");
const Suite = Mat.Suite;
const E = @import("execution.zig");
const Fixture = @import("../tests/rv64_word16_execution_fixture.zig").Fixture;
const Driver = @import("driver.zig");
const a = std.testing.allocator;
fn rejects(result: anyerror!void) !void {
    if (result) |_| return error.AcceptedWrongSuiteOrProof else |_| {}
}
test "Word16 suites admit only fixed q70 P26 fold1 or explicit fold4 before allocation" {
    const p = Suite.production();
    const f = Suite.experimentalFold4();
    try p.validate();
    try f.validate();
    try std.testing.expect(!std.mem.eql(u8, &try p.identity(), &try f.identity()));
    for (0..5) |mutation| {
        var bad = f;
        switch (mutation) {
            0 => bad.pcs.pow_bits = 0,
            1 => bad.pcs.fri_config.n_queries = 69,
            2 => bad.pcs.fri_config.fold_step = 0,
            3 => bad.pcs.fri_config.fold_step = 2,
            4 => bad.pcs.lifting_log_size = 0,
            else => unreachable,
        }
        var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
        try std.testing.expectError(error.UnsupportedWord16PcsSuite, Mat.Setup.initWithSuite(failing.allocator(), .{ .base = 0, .words = &.{} }, .{ .cpu_log = 5 }, bad));
        try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
    }
}
test "Word16 actual fold4 q70 proof fresh verification worker parity and bidirectional suite rejection" {
    var fixture = try Fixture.init(a);
    defer fixture.deinit();
    const g = Mat.Geometry{ .cpu_log = 5 };
    var production = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, g);
    defer production.deinit();
    var experiment = try Mat.Setup.initWithAuthorityAndSuite(a, &fixture.image.authority, g, Suite.experimentalFold4());
    defer experiment.deinit();
    // Fold scheduling changes no polynomial or fixed commitment geometry.
    try std.testing.expectEqualSlices(u8, &production.fixed_root.value, &experiment.fixed_root.value);
    const admission = Driver.admission(&fixture.image);
    var control = try E.prove(a, &production, admission, fixture.boundary, &fixture.tape, null);
    defer control.deinit(a);
    var proof = try E.prove(a, &experiment, admission, fixture.boundary, &fixture.tape, null);
    defer proof.deinit(a);
    try std.testing.expectEqualDeep(control.request.cpu, proof.request.cpu);
    try std.testing.expectEqualDeep(control.request.memory.initial, proof.request.memory.initial);
    try std.testing.expectEqualDeep(control.request.memory.terminal, proof.request.memory.terminal);
    try E.verify(a, &experiment, admission, proof);
    try std.testing.expectError(error.InvalidWord16ExecutionProof, E.verify(a, &production, admission, proof));
    try std.testing.expectError(error.InvalidWord16ExecutionProof, E.verify(a, &experiment, admission, control));
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 16, .stack_size = 1024 * 1024, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var parallel = try E.prove(a, &experiment, admission, fixture.boundary, &fixture.tape, null);
    defer parallel.deinit(a);
    try std.testing.expectEqualSlices(u8, proof.bytes, parallel.bytes);
    try E.verify(a, &experiment, admission, parallel);
}
test "Word16 actual fold4 FRI root and config relabel forgeries fail independent receiver" {
    var fixture = try Fixture.init(a);
    defer fixture.deinit();
    var key = try Mat.Setup.initWithAuthorityAndSuite(a, &fixture.image.authority, .{ .cpu_log = 5 }, Suite.experimentalFold4());
    defer key.deinit();
    const admission = Driver.admission(&fixture.image);
    var encoded = try E.prove(a, &key, admission, fixture.boundary, &fixture.tape, null);
    defer encoded.deinit(a);
    var proof = try wire.decodeProofBytesBinary(a, encoded.bytes);
    defer proof.deinit(a);
    try std.testing.expect(proof.commitment_scheme_proof.fri_proof.inner_layers.len > 0);
    proof.commitment_scheme_proof.fri_proof.inner_layers[0].commitment[0] ^= 1;
    const bytes = try wire.encodeProofBytesBinary(a, proof);
    defer a.free(bytes);
    var forged = encoded;
    forged.bytes = bytes;
    try rejects(E.verify(a, &key, admission, forged));
    proof.commitment_scheme_proof.fri_proof.inner_layers[0].commitment[0] ^= 1;
    proof.commitment_scheme_proof.config = Suite.production().config();
    const relabeled = try wire.encodeProofBytesBinary(a, proof);
    defer a.free(relabeled);
    forged.bytes = relabeled;
    try std.testing.expectError(error.InvalidWord16ExecutionProof, E.verify(a, &key, admission, forged));
}
test "Word16 canonical mixed service fold4 verifies all5 physical proofs and rejects mixed trusted suites" {
    const F = @import("../word16_global_execution/services/fixture.zig");
    const P = @import("../word16_global_execution/services/protocol.zig");
    const S = @import("../word16_global_execution/services/execution.zig");
    var c = try F.Case.initWithSuite(a, Suite.experimentalFold4());
    defer c.deinit();
    const keys = c.keys();
    const truths = c.truths();
    try S.verify(a, &keys, &truths, c.expected(), &c.bundle);
    var control = try F.Case.init(a);
    defer control.deinit();
    const production_keys = control.keys();
    const production_truths = control.truths();
    try S.verify(a, &production_keys, &production_truths, control.expected(), &control.bundle);
    try rejects(S.verify(a, &production_keys, &production_truths, control.expected(), &c.bundle));
    try rejects(S.verify(a, &keys, &truths, c.expected(), &control.bundle));
    try std.testing.expect(!std.mem.eql(u8, &c.bundle.manifest.digest, &control.bundle.manifest.digest));
    for (c.bundle.manifest.roots, control.bundle.manifest.roots) |x, y| {
        try std.testing.expectEqualSlices(u8, &x.fixed.bytes, &y.fixed.bytes);
        try std.testing.expectEqualSlices(u8, &x.main.bytes, &y.main.bytes);
    }

    var requests: [2]P.Request = .{ c.bundle.cpus[0].request, c.bundle.cpus[1].request };
    const old = c.setups[1].materials.suite;
    c.setups[1].materials.suite = Suite.production();
    defer c.setups[1].materials.suite = old;
    try std.testing.expectError(error.MixedWord16PcsSuites, P.admit(a, &keys, &truths, &requests, c.expected()));
    try std.testing.expectError(error.MixedWord16PcsSuites, S.verify(a, &keys, &truths, c.expected(), &c.bundle));
}
