//! Real PCS/STARK gate for one source-ROM dense call. Correctness-only profile;
//! no claim of production SSA/RAM/Wire service admission.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const front = @import("stwo_riscv_frontend");
const D = front.rv64_air.crypto.bn254_dense;
const C = D.fixture_component;
const M = C.M;
const Q = C.Q;
const kind = D.spec.Kind.multiply;
const L = C.Layout(kind);
const Trace = D.fixture_trace.Trace(kind);
const Backend = @import("stwo_cpu_backend").CpuBackend;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const Protocol = @import("../../word16_global_execution/services/gkr_local/worker_protocol.zig");
const MC = Protocol.MC;
const Channel = Protocol.Channel;
const Scheme = engine.pcs.ForField(Q).CommitmentSchemeProver(Backend, H, MC);
const Verifier = core.pcs.ForField(Q).verifier.CommitmentSchemeVerifier(H, MC);
const Wire = @import("stwo_proof_wire").ForField(Q);
const CONFIG = core.pcs.ForField(Q).PcsConfig{ .pow_bits = 0, .fri_config = .{ .log_last_layer_degree_bound = 0, .log_blowup_factor = 1, .n_queries = 12 } };
const INPUT = blk: {
    var a: [24]u256 = undefined;
    for (&a, 0..) |*v, i| v.* = if (i % 3 == 0) std.math.maxInt(u256) else if (i % 3 == 1) D.spec.B.BN254_P - 1 else 19 * i + 3;
    break :blk a;
};
fn expected() [12]u256 {
    return D.reference(INPUT[0..12].*, INPUT[12..24].*);
}
fn mix(channel: *Channel, input: *const [24]u256, output: [12]u256) void {
    CONFIG.mixInto(channel);
    channel.mixU32s(&.{ 0x44454e53, 1, 1, 8, 12, L.Row.MAIN, L.INTER, 21, 883205 });
    for (input) |value| {
        var words: [8]u32 = undefined;
        for (&words, 0..) |*v, i| v.* = @truncate(value >> @intCast(32 * i));
        channel.mixU32s(&words);
    }
    for (output) |value| {
        var words: [8]u32 = undefined;
        for (&words, 0..) |*v, i| v.* = @truncate(value >> @intCast(32 * i));
        channel.mixU32s(&words);
    }
}
fn columns(data: []const M, out: []engine.pcs.ColumnEvaluation) void {
    for (out, 0..) |*v, i| v.* = .{ .log_size = 8, .values = data[i * 256 ..][0..256] };
}
fn receive(a: std.mem.Allocator, bytes: []const u8, input: *const [24]u256, output: [12]u256, mutation: u8) !void {
    var proof = try Wire.decodeProofBytesBinary(a, bytes);
    var owns = true;
    defer if (owns) proof.deinit(a);
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4) return error.DenseProofShape;
    const ff = try Trace.fixedAlloc(a);
    defer a.free(ff);
    var fixed: [D.air.FIXED]engine.pcs.ColumnEvaluation = undefined;
    columns(ff, &fixed);
    var setup = try Scheme.init(a, CONFIG);
    defer setup.deinit(a);
    setup.setCompactPolynomialStorage(1);
    var scratch = Channel.init();
    try setup.commit(a, &fixed, &scratch);
    var fresh = try setup.roots(a);
    defer fresh.deinit(a);
    if (!std.mem.eql(u8, &roots[0], &fresh.items[0])) return error.DenseFixedAuthority;
    var verifier = try Verifier.init(a, CONFIG);
    defer verifier.deinit(a);
    var channel = Channel.init();
    mix(&channel, input, output);
    try verifier.commit(a, roots[0], &([_]u32{8} ** D.air.FIXED), &channel);
    try verifier.commit(a, roots[1], &([_]u32{8} ** L.Row.MAIN), &channel);
    const ch = C.draw(&channel);
    const claim = try Trace.expectedClaim(ch, output);
    channel.mixFelts(&.{ Q.zero(), claim });
    try verifier.commit(a, roots[2], &([_]u32{8} ** L.INTER), &channel);
    if (mutation != 0) {
        const col = switch (mutation) {
            1 => L.Row.OUTPUT,
            2 => L.Row.QUOTIENT,
            3 => L.Row.CARRY,
            else => L.Row.MULT,
        };
        proof.commitment_scheme_proof.sampled_values.items[1][col][0] = proof.commitment_scheme_proof.sampled_values.items[1][col][0].add(Q.one());
    }
    const component = C.Component(kind){ .input = input, .ch = ch, .claim = claim };
    const components = [_]core.air.components.ForField(Q).Component{component.asVerifierComponent()};
    owns = false;
    try core.verifier.ForField(Q).verify(H, MC, a, &components, &channel, &verifier, proof);
}
test "direct dense source ROM BYTE closure and fresh physical receiver" {
    const budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(std.testing.allocator, 2 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var trace = try Trace.init(a, &INPUT);
    defer trace.deinit();
    var fixed: [D.air.FIXED]engine.pcs.ColumnEvaluation = undefined;
    var main: [L.Row.MAIN]engine.pcs.ColumnEvaluation = undefined;
    var inter: [L.INTER]engine.pcs.ColumnEvaluation = undefined;
    columns(trace.fixed, &fixed);
    columns(trace.main, &main);
    var scheme = try Scheme.init(a, CONFIG);
    var owns = true;
    defer if (owns) scheme.deinit(a);
    scheme.setCompactPolynomialStorage(1);
    var channel = Channel.init();
    mix(&channel, &INPUT, expected());
    try scheme.commit(a, &fixed, &channel);
    try scheme.commit(a, &main, &channel);
    const ch = C.draw(&channel);
    const claim = try trace.generate(ch, expected());
    const component = C.Component(kind){ .input = &INPUT, .ch = ch, .claim = claim };
    // Numeric validity uses the same complete field/range emitter as OODS and
    // the packed domain adapter. No separate equation implementation.
    for (0..256) |r| {
        const v = trace.view(r);
        var values: [L.CONSTRAINTS]Q = undefined;
        var sink = front.rv64_air.evaluation.SinkFor(Q){ .values = &values };
        C.emit(kind, Q, &v, &INPUT, ch, claim, &sink);
        try std.testing.expectEqual(L.CONSTRAINTS, sink.count);
        for (values) |value| try std.testing.expect(value.isZero());
    }
    channel.mixFelts(&.{ Q.zero(), claim });
    columns(trace.inter, &inter);
    try scheme.commit(a, &inter, &channel);
    const components = [_]engine.air.component_prover.ForField(Q).ComponentProver{component.asProverComponent()};
    owns = false;
    var proof = try engine.prove.ForField(Q).prove(Backend, H, MC, a, &components, &channel, scheme);
    defer proof.deinit(a);
    const bytes = try Wire.encodeProofBytesBinary(a, proof);
    defer a.free(bytes);
    if (std.process.getEnvVarOwned(a, "STWO_DENSE_DIRECT_OUT")) |path| {
        defer a.free(path);
        var dir = try std.fs.cwd().makeOpenPath(path, .{});
        defer dir.close();
        const f = try dir.createFile("proof.bin", .{ .exclusive = true });
        defer f.close();
        try f.writeAll(bytes);
    } else |err| if (err != error.EnvironmentVariableNotFound) return err;
    try receive(a, bytes, &INPUT, expected(), 0);
    for (1..5) |m| try std.testing.expect(std.meta.isError(receive(a, bytes, &INPUT, expected(), @intCast(m))));
    var wrong_input = INPUT;
    wrong_input[0] ^= 1;
    try std.testing.expect(std.meta.isError(receive(a, bytes, &wrong_input, expected(), 0)));
    var wrong_output = expected();
    wrong_output[0] ^= 1;
    try std.testing.expect(std.meta.isError(receive(a, bytes, &INPUT, wrong_output, 0)));
    trace.main[L.Row.MULT * 256] = trace.main[L.Row.MULT * 256].add(M.one());
    try std.testing.expectError(error.DenseFixtureRangeNotClosed, trace.generate(ch, expected()));
    std.debug.print("OP_DENSE_DIRECT_PHYSICAL correctness_only=true degree=3 main={d} inter={d} proof_bytes={d}\n", .{ L.Row.MAIN, L.INTER, bytes.len });
}
test "direct dense complete equations degree three including source ROM and BYTE closure" {
    const View = struct {
        values: []const Q,
        pub fn fixed(v: *const @This(), c: usize) Q {
            return v.values[c];
        }
        pub fn main(v: *const @This(), c: usize) Q {
            return v.values[D.air.FIXED + c];
        }
        pub fn interaction(v: *const @This(), c: usize) Q {
            return v.values[D.air.FIXED + L.Row.MAIN + c];
        }
        pub fn previous(v: *const @This(), c: usize) Q {
            return v.values[D.air.FIXED + L.Row.MAIN + c].add(Q.one());
        }
    };
    var channel = Channel.init();
    const ch = C.draw(&channel);
    var values: [D.air.FIXED + L.Row.MAIN + L.INTER]Q = undefined;
    var residuals: [5][L.CONSTRAINTS]Q = undefined;
    for (0..5) |t| {
        for (&values, 0..) |*v, i| v.* = Q.fromBase(M.fromCanonical(@intCast(1 + i))).add(Q.fromBase(M.fromCanonical(@intCast((i + 7) * t))));
        const view = View{ .values = &values };
        var sink = front.rv64_air.evaluation.SinkFor(Q){ .values = &residuals[t] };
        C.emit(kind, Q, &view, &INPUT, ch, Q.one(), &sink);
        try std.testing.expectEqual(L.CONSTRAINTS, sink.count);
    }
    for (0..L.CONSTRAINTS) |i| {
        const diff = residuals[0][i].sub(residuals[1][i].mulM31(M.fromCanonical(4))).add(residuals[2][i].mulM31(M.fromCanonical(6))).sub(residuals[3][i].mulM31(M.fromCanonical(4))).add(residuals[4][i]);
        if (!diff.isZero()) {
            std.debug.print("BAD_DEGREE index={d}\n", .{i});
            return error.DenseDegreeAboveThree;
        }
    }
}
