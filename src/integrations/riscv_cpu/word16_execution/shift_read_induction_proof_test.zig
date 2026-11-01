//! Valid physical proof of a false SHIFT FUNCTION witness with canonical outputs.
//! The closed CPU receiver, not native advice validation, must reject it.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Backend = @import("stwo_cpu_backend").CpuBackend;
const A = @import("stwo_riscv_frontend").rv64_air;
const X = A.memory.load_store_v2;
const SHIFT = A.word16_v1.shift_word_packed_experiment;
const R = A.memory.closed_ram;
const P = @import("protocol.zig");
const Mat = @import("setup.zig");
const Sources = @import("sources.zig");
const Components = @import("components.zig").Components;
const Execution = @import("execution.zig");
const Driver = @import("driver.zig");
const Q = X.types.Q;
const M = X.types.M;
const a = std.testing.allocator;
const n: usize = 32;
fn repair(main: []const M, inter: []M, ch: SHIFT.lookup.Challenges) !SHIFT.lookup.Claims {
    var claims = SHIFT.lookup.Claims{ .shift = Q.zero(), .range16 = Q.zero(), .function = Q.zero() };
    for (0..n) |logical| {
        const pos = R.trace.physical(logical, 5);
        var m: [SHIFT.lookup.MAIN]Q = undefined;
        for (&m, 0..) |*v, column| v.* = Q.fromBase(main[column * n + pos]);
        const row = SHIFT.equations.rowFromColumnsFor(Q, &m);
        for (0..SHIFT.lookup.encoding.PAIRS) |pair| {
            const x = try SHIFT.lookup.unitDenominatorFor(Q, &row, 2 * pair, ch).inv();
            const y = try SHIFT.lookup.unitDenominatorFor(Q, &row, 2 * pair + 1, ch).inv();
            R.trace.store(inter, n, pos, 4 * pair, x.mul(y));
            if (2 * pair < 5) claims.shift = claims.shift.add(x) else claims.range16 = claims.range16.add(x);
            if (2 * pair + 1 < 5) claims.shift = claims.shift.add(y) else claims.range16 = claims.range16.add(y);
        }
        const inverse = try ch.function.denominatorFor(Q, row.payload).inv();
        R.trace.store(inter, n, pos, SHIFT.lookup.FUNCTION_INVERSE, inverse);
        claims.function = claims.function.sub(inverse.mul(m[SHIFT.equations.LOCAL_MAIN]));
        R.trace.store(inter, n, pos, SHIFT.lookup.PREFIX, claims.shift.add(claims.range16).add(claims.function));
    }
    R.trace.center(inter, n, SHIFT.lookup.PREFIX, claims.shift.add(claims.range16).add(claims.function));
    return claims;
}
test "valid physical SHIFT proof with unqueried B high coordinates fails closed CPU FUNCTION authority" {
    var fixture = try @import("../tests/rv64_word16_execution_fixture.zig").Fixture.init(a);
    defer fixture.deinit();
    var setup = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, .{ .cpu_log = 5, .alu_log = 5, .binary_log = 5, .shift_log = 5, .jalr_log = 5, .division_log = 5, .multiplication_log = 5, .ls_log = 5, .boundary_log = 5 });
    defer setup.deinit();
    const admission = Driver.admission(&fixture.image);
    var source = try Sources.Source.init(a, &setup.materials, admission.image, fixture.boundary, 1, &fixture.tape);
    defer source.deinit();
    const request = source.request();
    const m = source.shift.main;
    const pos = for (0..n) |physical| {
        if (m[SHIFT.equations.LOCAL_MAIN * n + physical].v != 0) break physical;
    } else return error.MissingShiftFact;
    var values: [SHIFT.lookup.MAIN]Q = undefined;
    for (&values, 0..) |*v, column| v.* = Q.fromBase(m[column * n + pos]);
    var row = SHIFT.equations.rowFromColumnsFor(Q, &values);
    row.payload[6] = A.evaluation.q(core.fields.m31.Modulus - 1);
    row.payload[7] = A.evaluation.q(65536);
    row.payload[8] = A.evaluation.q((core.fields.m31.Modulus + 1) / 2);
    var residuals: [SHIFT.equations.CONSTRAINTS]Q = undefined;
    var sink = A.evaluation.Sink{ .values = &residuals };
    SHIFT.equations.emitFor(Q, &row, &sink);
    for (residuals) |value| try std.testing.expect(value.isZero());
    for (0..SHIFT.equations.RANGE_QUERIES) |query| try std.testing.expect((try SHIFT.equations.rangeValueFor(Q, &row, query).tryIntoM31()).v < 65536);
    for (row.payload[9..13]) |value| try std.testing.expect((try value.tryIntoM31()).v < 65536);
    for (SHIFT.equations.rowToColumnsFor(Q, &row), 0..) |value, column| m[column * n + pos] = try value.tryIntoM31();
    const actual = try a.dupe(M, m);
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
    const range_claim = claims.shift.range16;
    const shift_claim = claims.shift.shift;
    claims.shift = try repair(actual, source.shift.interaction, .{ .shift = draw.shift_, .range16 = draw.memory.range16, .function = .{ .offset = draw.cpu.function.offset, .coefficients = draw.cpu.function.coefficients } });
    try std.testing.expect(range_claim.eql(claims.shift.range16));
    try std.testing.expect(shift_claim.eql(claims.shift.shift));
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
