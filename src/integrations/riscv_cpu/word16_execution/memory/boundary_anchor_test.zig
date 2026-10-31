//! Deliberately bypasses native canonical projections. The full physical proof
//! is valid and its global ledger closes; only independently anchored boundary
//! tuple authority rejects it. Never expose this permissive verifier in code.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Backend = @import("stwo_cpu_backend").CpuBackend;
const A = @import("stwo_riscv_frontend").rv64_air;
const R = A.memory.closed_ram;
const X = A.memory.load_store_v2;
const Mat = @import("../setup.zig");
const P = @import("../protocol.zig");
const Sources = @import("../sources.zig");
const Components = @import("../components.zig").Components;
const Execution = @import("../execution.zig");
const Driver = @import("../driver.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const a = std.testing.allocator;
const n: usize = 32;
fn ghostMain(main: []M) void {
    const pos = R.trace.physical(2, 5);
    main[n + pos] = main[n + pos].add(M.fromCanonical(65536));
    main[2 * n + pos] = main[2 * n + pos].sub(M.one());
    main[18 * n + pos] = M.zero();
}
fn repairRam(main: []const M, source: *X.boundary_source.Source, ch: R.types.RamChallenges) !Q {
    var sum = Q.zero();
    for (0..n) |logical| {
        const pos = R.trace.physical(logical, 5);
        var row: [23]Q = undefined;
        for (&row, 0..) |*v, c| v.* = Q.fromBase(main[c * n + pos]);
        const inv = try ch.denominatorFor(Q, R.equations.ramTuple(Q, if (source.kind == .initial) .initial else .terminal, &row, false)).inv();
        R.trace.store(source.interaction, n, pos, 0, inv);
        const value = inv.mul(row[0]);
        sum = if (source.kind == .initial) sum.sub(value) else sum.add(value);
        R.trace.store(source.interaction, n, pos, 4, sum);
    }
    R.trace.center(source.interaction, n, 4, sum);
    return sum;
}
fn verifyPhysical(setup: *const Mat.Setup, admission: Execution.Admission, encoded: Execution.Encoded) !void {
    const wire = @import("stwo_proof_wire");
    var proof = try wire.decodeProofBytesBinary(a, encoded.bytes);
    var owns = true;
    defer if (owns) proof.deinit(a);
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(P.T.P.Hasher, P.T.P.MerkleChannel).init(a, P.T.P.config());
    defer verifier.deinit(a);
    var channel = P.T.P.Channel{};
    try P.mix(&channel, setup, encoded.request, admission.image_identity);
    for ([_]usize{ 0, 1 }) |tree| {
        const logs = try setup.materials.logs(a, tree);
        defer a.free(logs);
        try verifier.commit(a, proof.commitment_scheme_proof.commitments.items[tree], logs, &channel);
    }
    const draw = P.draw(&channel);
    channel.mixFelts(&encoded.claims.values());
    const logs = try setup.materials.logs(a, 2);
    defer a.free(logs);
    try verifier.commit(a, proof.commitment_scheme_proof.commitments.items[2], logs, &channel);
    var components = try Components.init(&setup.materials, encoded.request, draw, encoded.claims);
    const handles = try components.verifiers(a);
    defer a.free(handles);
    owns = false;
    try core.verifier.verify(P.T.P.Hasher, P.T.P.MerkleChannel, a, handles, &channel, &verifier, proof);
}
test "valid full proof with balanced noncanonical boundary ghosts is rejected by independent RAM tuple authority" {
    var fixture = try @import("../../tests/rv64_word16_execution_fixture.zig").Fixture.init(a);
    defer fixture.deinit();
    var setup = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, .{ .cpu_log = 5, .alu_log = 5, .binary_log = 5, .shift_log = 5, .jalr_log = 5, .division_log = 5, .multiplication_log = 5, .ls_log = 5, .boundary_log = 5 });
    defer setup.deinit();
    const admission = Driver.admission(&fixture.image);
    var prepared = try Sources.Prepared.init(a, &setup.materials.program, fixture.boundary, 1, 5, &fixture.tape, .{ .deduplicate_binary = false, .jalr_log = 5 });
    defer prepared.deinit();
    var collected = try @import("collector.zig").collect(a, admission.image, prepared.cpu.?.memory.items, 1);
    defer collected.deinit();
    try std.testing.expectEqual(@as(usize, 1), collected.initial.len);
    const initial = try a.alloc(R.types.Cell, 3);
    const terminal = try a.alloc(R.types.Cell, 3);
    initial[0] = collected.initial[0];
    terminal[0] = collected.terminal[0];
    for ([_]u64{ 0x2108000, 0x2112000 }, 1..) |address, j| {
        initial[j] = .{ .address = address, .state = .{ .value = 0, .rights = 3 } };
        terminal[j] = initial[j]; // Untouched words carry the same canonical state.
    }
    const memory = try @import("prepared.zig").Prepared.initOwnedForGlobalRamIndependent(a, collected.events, initial, terminal, 1, 5, 5, 5);
    var source = try Sources.Source.fromPreparedWithOwnedMemory(a, &setup.materials, &prepared, memory);
    defer source.deinit();
    const request = source.request();
    try admission.validate(&setup, request);
    ghostMain(source.memory.initial.main);
    ghostMain(source.memory.terminal.main);
    const im = try a.dupe(M, source.memory.initial.main);
    defer a.free(im);
    const tm = try a.dupe(M, source.memory.terminal.main);
    defer a.free(tm);
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
    var claims = try source.generate(draw);
    claims.initial.ram = try repairRam(im, &source.memory.initial, draw.memory.ram);
    claims.terminal.ram = try repairRam(tm, &source.memory.terminal, draw.memory.ram);
    try claims.validate(); // Ghost debts cancel; aggregate-only validation passes.
    const expected_initial = try X.boundary_source.expectedClaim(request.memory.initial, true, draw.memory.ram);
    const expected_terminal = try X.boundary_source.expectedClaim(request.memory.terminal, false, draw.memory.ram);
    try std.testing.expect(!claims.initial.ram.eql(expected_initial));
    try std.testing.expect(!claims.terminal.ram.eql(expected_terminal));
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
    var encoded = Execution.Encoded{ .bytes = bytes, .claims = claims, .request = request };
    // Fresh key and actual polynomial verification demonstrate this is not
    // rejection by native advice construction or a broken underlying proof.
    var fresh = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, setup.materials.geometry);
    defer fresh.deinit();
    try verifyPhysical(&fresh, admission, encoded);
    try std.testing.expectError(error.UntrustedWord16MemoryBoundaryClaim, Execution.verify(a, &fresh, admission, encoded));
    // Replacing both ghosts with public debts preserves closure but changes FS.
    encoded.claims.initial.ram = expected_initial;
    encoded.claims.terminal.ram = expected_terminal;
    try encoded.claims.validate();
    if (Execution.verify(a, &fresh, admission, encoded)) |_| return error.ReboundBoundaryProofAccepted else |_| {}
}
