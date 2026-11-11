//! Toy q12/B2 physical gate only; no production SSA or pairing acceptance.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const C = @import("equations.zig");
const T = @import("trace.zig").Trace;
const Component = @import("component.zig").Component();
const S = C.S;
const W = C.W;
const M = C.M;
const O = C.O;
const Backend = @import("stwo_cpu_backend").CpuBackend;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const Protocol = @import("../../word16_global_execution/services/gkr_local/worker_protocol.zig");
const MC = Protocol.MC;
const Channel = Protocol.Channel;
const Scheme = engine.pcs.ForField(O).CommitmentSchemeProver(Backend, H, MC);
const Verifier = core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(H, MC);
const Wire = @import("stwo_proof_wire").ForField(O);
const CONFIG = core.pcs.ForField(O).PcsConfig{ .pow_bits = 0, .fri_config = .{ .log_last_layer_degree_bound = 0, .log_blowup_factor = 1, .n_queries = 12 } };
fn mix(ch: *Channel, input: *const W.Inputs, output: u256) void {
    CONFIG.mixInto(ch);
    ch.mixU32s(&.{ 0x4d414331, 12, 1, 8, 22, 1106, 40, 353, 1 << 21 });
    for (input) |value| {
        var words: [8]u32 = undefined;
        for (&words, 0..) |*x, i| x.* = @truncate(value >> @intCast(32 * i));
        ch.mixU32s(&words);
    }
    var words: [8]u32 = undefined;
    for (&words, 0..) |*x, i| x.* = @truncate(output >> @intCast(32 * i));
    ch.mixU32s(&words);
}
fn receive(a: std.mem.Allocator, bytes: []const u8, input: *const W.Inputs, output: u256, coefficients: W.Coefficients) !void {
    if (bytes.len > 16 << 20) return error.Mac12ProofByteCap;
    var proof = try Wire.decodeProofBytesBinary(a, bytes);
    var owns = true;
    defer if (owns) proof.deinit(a);
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4) return error.Mac12ProofShape;
    const ff = try T.fixedAlloc(a, coefficients);
    defer a.free(ff);
    var fixed: [C.FIXED]engine.pcs.ColumnEvaluation = undefined;
    T.columns(ff, &fixed);
    var setup = try Scheme.init(a, CONFIG);
    defer setup.deinit(a);
    setup.setCompactPolynomialStorage(1);
    var scratch = Channel.init();
    try setup.commit(a, &fixed, &scratch);
    var expected = try setup.roots(a);
    defer expected.deinit(a);
    if (!std.mem.eql(u8, &roots[0], &expected.items[0])) return error.Mac12FixedAuthority;
    var verifier = try Verifier.init(a, CONFIG);
    defer verifier.deinit(a);
    var ch = Channel.init();
    mix(&ch, input, output);
    try verifier.commit(a, roots[0], &([_]u32{8} ** C.FIXED), &ch);
    try verifier.commit(a, roots[1], &([_]u32{8} ** C.MAIN), &ch);
    const beta = ch.drawSecureFelt();
    try verifier.commit(a, roots[2], &([_]u32{8} ** C.INTER), &ch);
    const component = Component{ .input = input, .output = output, .beta = beta };
    const components = [_]core.air.components.ForField(O).Component{component.asVerifierComponent()};
    owns = false;
    try core.verifier.ForField(O).verify(H, MC, a, &components, &ch, &verifier, proof);
}
fn prove(a: std.mem.Allocator, trace: *T, input: *const W.Inputs, output: u256, forged: bool) ![]u8 {
    var fixed: [C.FIXED]engine.pcs.ColumnEvaluation = undefined;
    T.columns(trace.fixed, &fixed);
    var main: [C.MAIN]engine.pcs.ColumnEvaluation = undefined;
    T.columns(trace.main, &main);
    var inter: [C.INTER]engine.pcs.ColumnEvaluation = undefined;
    var scheme = try Scheme.init(a, CONFIG);
    var owns = true;
    defer if (owns) scheme.deinit(a);
    scheme.setCompactPolynomialStorage(1);
    var ch = Channel.init();
    mix(&ch, input, output);
    try scheme.commit(a, &fixed, &ch);
    try scheme.commit(a, &main, &ch);
    const beta = ch.drawSecureFelt();
    try trace.generate(beta);
    T.columns(trace.inter, &inter);
    try scheme.commit(a, &inter, &ch);
    const component = Component{ .input = input, .output = output, .beta = beta };
    const components = [_]engine.air.component_prover.ForField(O).ComponentProver{component.asProverComponent()};
    owns = false;
    var diagnostic: ?@import("stwo_prover_api").ProveDiagnostic = null;
    var failed: ?core.proof.ForField(O).ExtendedStarkProof(H) = null;
    var refused = false;
    var result = engine.prove.ForField(O).proveExWithExecutionDiagnosedRetainingFailure(Backend, H, MC, a, &components, &ch, scheme, false, null, null, null, &diagnostic, &failed) catch |err| blk: {
        if (err != error.ConstraintsNotSatisfied) return err;
        refused = true;
        break :blk failed orelse return error.Mac12MissingFailedProof;
    };
    defer result.aux.deinit(a);
    var proof = result.proof;
    try std.testing.expectEqual(forged, refused);
    defer proof.deinit(a);
    return Wire.encodeProofBytesBinary(a, proof);
}
test "MAC12 bounded physical signed row BYTE closure independent receiver and coherent aliases" {
    const budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(std.testing.allocator, 2 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    const input: W.Inputs = @splat(S.B.P - 1);
    for ([_]i32{ 18, -18 }) |coefficient| {
        const coefficients: W.Coefficients = @splat(coefficient);
        const row = try W.fill(&input, coefficients);
        const output: u256 = @intCast(W.read(&row, S.OUTPUT, 32));
        var trace = try T.init(a, &input, coefficients, false);
        defer trace.deinit();
        const bytes = try prove(a, &trace, &input, output, false);
        defer a.free(bytes);
        try receive(a, bytes, &input, output, coefficients);
        var wrong = input;
        wrong[0] -= 1;
        try std.testing.expect(std.meta.isError(receive(a, bytes, &wrong, output, coefficients)));
        try std.testing.expect(std.meta.isError(receive(a, bytes, &input, output + 1, coefficients)));
        var wrong_coefficients = coefficients;
        wrong_coefficients[0] *= -1;
        try std.testing.expectError(error.Mac12FixedAuthority, receive(a, bytes, &input, output, wrong_coefficients));
        var alias = try T.init(a, &input, coefficients, true);
        defer alias.deinit();
        const alias_bytes = try prove(a, &alias, &input, output, true);
        defer a.free(alias_bytes);
        try std.testing.expectError(error.OodsNotMatching, receive(a, alias_bytes, &input, output, coefficients));
        if (std.process.getEnvVarOwned(a, "STWO_MAC12_OUT")) |path| {
            defer a.free(path);
            var dir = try std.fs.cwd().makeOpenPath(path, .{});
            defer dir.close();
            const file = try dir.createFile(if (coefficient > 0) "positive.bin" else "negative.bin", .{ .exclusive = true });
            defer file.close();
            try file.writeAll(bytes);
            const failed_file = try dir.createFile(if (coefficient > 0) "positive-plus-p.unverified.bin" else "negative-plus-p.unverified.bin", .{ .exclusive = true });
            defer failed_file.close();
            try failed_file.writeAll(alias_bytes);
        } else |err| if (err != error.EnvironmentVariableNotFound) return err;
        std.debug.print("MAC12_PHYSICAL correctness_only=true sign={d} fixed={d} main={d} inter={d} proof_bytes={d}\n", .{ coefficient, C.FIXED, C.MAIN, C.INTER, bytes.len });
    }
    const usage = budget.snapshot();
    try std.testing.expectEqual(@as(usize, 0), usage.live_bytes);
    std.debug.print("MAC12_PHYSICAL_MEMORY peak={d} final={d} cap={d}\n", .{ usage.peak_live_bytes, usage.live_bytes, usage.limit });
}
