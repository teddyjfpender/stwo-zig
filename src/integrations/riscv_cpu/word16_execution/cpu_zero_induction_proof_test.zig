//! A valid physical proof must not turn a producer enable flag into ROM authority.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Backend = @import("stwo_cpu_backend").CpuBackend;
const A = @import("stwo_riscv_frontend").rv64_air;
const X = A.word16_execution;
const R = A.memory.closed_ram;
const P = @import("protocol.zig");
const Mat = @import("setup.zig");
const Sources = @import("sources.zig");
const Components = @import("components.zig").Components;
const Execution = @import("execution.zig");
const Driver = @import("driver.zig");
const Q = A.evaluation.Q;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
const n: usize = 32;
fn repair(main: []const M, inter: []M, public: X.types.Inputs, ch: X.types.Challenges) !Q {
    var claim = Q.zero();
    for (0..n) |logical| {
        const pos = R.trace.physical(logical, 5);
        var row: [X.layout.main.COUNT]M = undefined;
        for (&row, 0..) |*v, column| v.* = main[column * n + pos];
        const fixed = [_]M{ M.fromCanonical(@intCast(logical)), M.fromCanonical(@intFromBool(logical == 0)), M.fromCanonical(@intFromBool(logical == n - 1)) };
        const ds = X.equations.nativeDenominators(&fixed, &row, public, ch);
        var inverses: [9]Q = undefined;
        for (X.equations.inverseDenominatorsFor(Q, ds), &inverses, 0..) |denominator, *inverse, i| {
            inverse.* = try denominator.inv();
            R.trace.store(inter, n, pos, 4 * i, inverse.*);
        }
        claim = claim.add(X.equations.nativeContribution(ds, &row, inverses));
        R.trace.store(inter, n, pos, X.layout.inter.sum, claim);
    }
    R.trace.center(inter, n, X.layout.inter.sum, claim);
    return claim;
}
test "valid physical CPU proof with a forged zero-register enable fails closed ROM and REG closure" {
    var fixture = try @import("../tests/rv64_word16_execution_fixture.zig").Fixture.init(a);
    defer fixture.deinit();
    var setup = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, .{ .cpu_log = 5 });
    defer setup.deinit();
    const admission = Driver.admission(&fixture.image);
    var source = try Sources.Source.init(a, &setup.materials, admission.image, fixture.boundary, 1, &fixture.tape);
    defer source.deinit();
    const request = source.request();
    const pos = R.trace.physical(0, 5);
    const L = X.layout;
    // LUI's rs1 is x0 with canonical value and predecessor clock zero. Only
    // enable changes: the derived zero flag now disagrees with immutable ROM.
    try std.testing.expectEqual(M.zero(), source.cpu.main[(L.main.registers + 0) * n + pos]);
    try std.testing.expectEqual(M.zero(), source.cpu.main[(L.main.enabled + 0) * n + pos]);
    source.cpu.main[(L.main.enabled + 0) * n + pos] = M.one();
    const actual = try a.dupe(M, source.cpu.main);
    defer a.free(actual);
    var scheme = try P.T.Scheme.init(a, P.T.P.config());
    var owns = true;
    defer if (owns) scheme.deinit(a);
    scheme.setCompactPolynomialStorage(5);
    var channel = P.T.P.Channel{};
    try P.mix(&channel, &setup, request, admission.image_identity);
    try setup.appendFixed(a, &scheme, &channel);
    const main = try source.columns(a, 1);
    defer a.free(main);
    try scheme.commitBorrowedStreaming(a, main, 8, &channel);
    try source.releaseMain();
    const draw = P.draw(&channel);
    var claims = (try source.generateForDelegationJoin(draw)).physical;
    // Every other debt, including the adjusted retained-range ledger, closes.
    try claims.validate();
    claims.cpu = try repair(actual, source.cpu.interaction, try X.types.inputs(request.cpu, request.epoch, 5), draw.cpu);
    try std.testing.expectError(error.UnclosedExecutionRelations, claims.validate());
    channel.mixFelts(&claims.values());
    const inter = try source.columns(a, 2);
    defer a.free(inter);
    try scheme.commitBorrowedStreaming(a, inter, 8, &channel);
    source.releaseCommittedInteraction();
    var components = try Components.init(&setup.materials, request, draw, claims);
    const handles = try components.provers(a);
    defer a.free(handles);
    owns = false;
    var result = try engine.prove.proveExWithRecorder(Backend, P.T.P.Hasher, P.T.P.MerkleChannel, a, handles, &channel, scheme, false, null);
    defer result.aux.deinit(a);
    defer result.proof.deinit(a);
    const bytes = try @import("stwo_proof_wire").encodeProofBytesBinary(a, result.proof);
    defer a.free(bytes);
    const encoded = Execution.Encoded{ .bytes = bytes, .claims = claims, .request = request };
    var fresh = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, setup.materials.geometry);
    defer fresh.deinit();
    try @import("memory/boundary_anchor_test.zig").verifyPhysical(&fresh, admission, encoded);
    try std.testing.expectError(error.UnclosedExecutionRelations, Execution.verify(a, &fresh, admission, encoded));
}
