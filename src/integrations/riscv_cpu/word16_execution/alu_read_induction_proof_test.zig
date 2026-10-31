//! Valid physical proof of a false ALU FUNCTION witness with canonical outputs.
//! The closed CPU receiver, not native advice validation, must reject it.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Backend = @import("stwo_cpu_backend").CpuBackend;
const A = @import("stwo_riscv_frontend").rv64_air;
const X = A.memory.load_store_v2;
const ALU = A.word16_v1.alu_experiment;
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
fn repair(main: []const M, inter: []M, ch: ALU.lookup.Challenges) !ALU.lookup.Claims {
    var claims = ALU.lookup.Claims{ .range16 = Q.zero(), .function = Q.zero() };
    for (0..n) |logical| {
        const pos = R.trace.physical(logical, 5);
        var m: [ALU.lookup.MAIN]Q = undefined;
        for (&m, 0..) |*v, column| v.* = Q.fromBase(main[column * n + pos]);
        const row = ALU.lookup.rowFromColumnsFor(Q, &m);
        for (0..ALU.equations.RANGE_QUERIES / 2) |pair| {
            const a_inverse = try ch.range16.denominatorFor(Q, ALU.equations.rangeValueFor(Q, &row, 2 * pair)).inv();
            const b_inverse = try ch.range16.denominatorFor(Q, ALU.equations.rangeValueFor(Q, &row, 2 * pair + 1)).inv();
            R.trace.store(inter, n, pos, 4 * pair, a_inverse.mul(b_inverse));
            claims.range16 = claims.range16.add(a_inverse).add(b_inverse);
        }
        const inverse = try ch.function.denominatorFor(Q, row.payload).inv();
        R.trace.store(inter, n, pos, ALU.lookup.FUNCTION_INVERSE, inverse);
        claims.function = claims.function.sub(inverse.mul(m[ALU.equations.LOCAL_MAIN]));
        R.trace.store(inter, n, pos, ALU.lookup.PREFIX, claims.range16.add(claims.function));
    }
    R.trace.center(inter, n, ALU.lookup.PREFIX, claims.range16.add(claims.function));
    return claims;
}
test "valid physical ALU proof with half-field noncanonical reads fails the closed canonical CPU FUNCTION relation" {
    var fixture = try @import("../tests/rv64_word16_execution_fixture.zig").Fixture.init(a);
    defer fixture.deinit();
    var setup = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, .{ .cpu_log = 5, .alu_log = 5, .binary_log = 5, .shift_log = 5, .jalr_log = 5, .division_log = 5, .multiplication_log = 5, .ls_log = 5, .boundary_log = 5 });
    defer setup.deinit();
    const admission = Driver.admission(&fixture.image);
    var source = try Sources.Source.init(a, &setup.materials, admission.image, fixture.boundary, 1, &fixture.tape);
    defer source.deinit();
    const request = source.request();
    const m = source.alu.main;
    const pos = for (0..n) |physical| {
        if (m[ALU.equations.LOCAL_MAIN * n + physical].v != 0 and m[physical].v == 0 and m[4 * n + physical].v == 0 and m[8 * n + physical].v == 0 and m[12 * n + physical].v == 0) break physical;
    } else return error.MissingAddFact;
    var values: [ALU.lookup.MAIN]Q = undefined;
    for (&values, 0..) |*v, column| v.* = Q.fromBase(m[column * n + pos]);
    var row = ALU.lookup.rowFromColumnsFor(Q, &values);
    const honest = row;
    const half = A.evaluation.q((core.fields.m31.Modulus + 1) / 2);
    row.payload[4] = half;
    row.payload[8] = half;
    row.low[0] = half;
    row.low[1] = half;
    row.sum[3] = Q.one();
    row.payload[12] = Q.one();
    var residuals: [ALU.equations.CONSTRAINTS]Q = undefined;
    var sink = A.evaluation.Sink{ .values = &residuals };
    ALU.equations.emitFor(Q, &row, &sink);
    for (residuals) |value| try std.testing.expect(value.isZero());
    const logical = for (0..n) |i| {
        if (R.trace.physical(i, 5) == pos) break i;
    } else unreachable;
    const all_counts = @constCast(source.range16.counts);
    for (0..ALU.equations.RANGE_QUERIES) |query| {
        const before = (try ALU.equations.rangeValueFor(Q, &honest, query).tryIntoM31()).v;
        const after = (try ALU.equations.rangeValueFor(Q, &row, query).tryIntoM31()).v;
        try std.testing.expect(after < 65536);
        source.alu.range16_counts[before] -= 1;
        source.alu.range16_counts[after] += 1;
        all_counts[before] -= 1;
        all_counts[after] += 1;
        source.range16.main[R.trace.physical(before, 16)] = M.fromCanonical(@intCast(all_counts[before]));
        source.range16.main[R.trace.physical(after, 16)] = M.fromCanonical(@intCast(all_counts[after]));
        source.alu.metadata[logical].range_indices[query] = @intCast(after);
    }
    for (ALU.lookup.rowToColumnsFor(Q, row), 0..) |value, column| m[column * n + pos] = try value.tryIntoM31();
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
    const range_claim = claims.alu.range16;
    claims.alu = try repair(actual, source.alu.interaction, .{ .range16 = draw.memory.range16, .function = .{ .offset = draw.cpu.function.offset, .coefficients = draw.cpu.function.coefficients } });
    try std.testing.expect(range_claim.eql(claims.alu.range16));
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
