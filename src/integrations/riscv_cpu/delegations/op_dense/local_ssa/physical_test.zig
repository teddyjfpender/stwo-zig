//! Physical two-operation local SSA fixture, not a CPU/VM service admission.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const D = A.crypto.bn254_dense;
const N = @import("native.zig");
const P = @import("projection.zig");
const C = @import("component.zig");
const T = @import("trace.zig");
const Q = N.Q;
const Backend = @import("stwo_cpu_backend").CpuBackend;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const Protocol = @import("../../../word16_global_execution/services/gkr_local/worker_protocol.zig");
const MC = Protocol.MC;
const Channel = Protocol.Channel;
const Scheme = engine.pcs.ForField(Q).CommitmentSchemeProver(Backend, H, MC);
const Verifier = core.pcs.ForField(Q).verifier.CommitmentSchemeVerifier(H, MC);
const Wire = @import("stwo_proof_wire").ForField(Q);
const CONFIG = core.pcs.ForField(Q).PcsConfig{ .pow_bits = 0, .fri_config = .{ .log_last_layer_degree_bound = 0, .log_blowup_factor = 1, .n_queries = 12 } };
const FIXED_LOGS = T.logs(0);
const MAIN_LOGS = T.logs(1);
const INTER_LOGS = T.logs(2);
const INPUT_A: [12]u256 = blk: {
    var a: [12]u256 = undefined;
    for (&a, 0..) |*x, i| x.* = if (i == 0) std.math.maxInt(u256) else 191 * i + 37;
    break :blk a;
};
const INPUT_B: [12]u256 = blk: {
    var b: [12]u256 = undefined;
    for (&b, 0..) |*x, i| x.* = if (i == 7) D.spec.B.BN254_P - 1 else 79 * i + 11;
    break :blk b;
};
fn expectedOutput() [12]u256 {
    return D.reference(D.reference(INPUT_A, INPUT_A), INPUT_B);
}
fn mix(ch: *Channel, public: *const [24]u256, out: [12]u256) void {
    CONFIG.mixInto(ch);
    ch.mixU32s(&.{ 0x44535341, 1, 5, 8, 9, 8, 16, 32, 40, 16 });
    const digest = N.statement(public, out);
    var words: [8]u32 = undefined;
    for (&words, 0..) |*x, i| x.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    ch.mixU32s(&words);
}
fn mixReceipt(ch: *Channel, digest: core.crypto.poseidon2_m31_sponge.Digest) void {
    var words: [9]u32 = undefined;
    for (&words, 0..) |*x, i| x.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    ch.mixU32s(&words);
}
fn parts(a: std.mem.Allocator, w: *const D.chain.Witness) ![4]T.Part {
    var result: [4]T.Part = undefined;
    var n: usize = 0;
    errdefer for (result[0..n]) |*part| part.deinit();
    inline for (T.ORDER, 0..) |r, i| {
        result[i] = try T.Part.init(r, a, w);
        n += 1;
    }
    return result;
}
fn columns(comptime tree: usize, pp: *const [4]T.Part) [T.width(tree)]engine.pcs.ColumnEvaluation {
    var out: [T.width(tree)]engine.pcs.ColumnEvaluation = undefined;
    inline for (T.ORDER, 0..) |role, i| {
        const offset = T.offsets(role)[tree];
        const width = switch (tree) {
            0 => C.fixedWidth(role),
            1 => C.mainWidth(role),
            2 => C.interactionWidth(role),
            else => unreachable,
        };
        pp[i].columns(tree, out[offset..][0..width]);
    }
    return out;
}
fn data(a: std.mem.Allocator, pending: *const N.Pending) ![6]P.Data {
    var out: [6]P.Data = undefined;
    var n: usize = 0;
    errdefer for (out[0..n]) |*d| d.deinit();
    for (&out, 0..) |*d, i| {
        d.* = try P.Data.init(a, i, &pending.artifact, pending.beta, pending.ssa, pending.eta);
        n += 1;
    }
    return out;
}
const Components = struct {
    initial: C.Component(.initial),
    square: C.Component(.square),
    multiply: C.Component(.multiply),
    table: C.Component(.table),
    fn init(dd: *const [6]P.Data, wire: D.chain.Wire, claim: Q) Components {
        return .{
            .initial = .{ .data = .{&dd[3]}, .wire = wire, .claim = Q.zero(), .offsets = T.offsets(.initial) },
            .square = .{ .data = .{ &dd[0], &dd[4] }, .wire = wire, .claim = Q.zero(), .offsets = T.offsets(.square) },
            .multiply = .{ .data = .{ &dd[1], &dd[5] }, .wire = wire, .claim = claim, .offsets = T.offsets(.multiply) },
            .table = .{ .data = .{&dd[2]}, .wire = wire, .claim = Q.zero(), .offsets = T.offsets(.table) },
        };
    }
    fn prover(self: *const Components) [4]engine.air.component_prover.ForField(Q).ComponentProver {
        return .{ self.initial.asProverComponent(), self.square.asProverComponent(), self.multiply.asProverComponent(), self.table.asProverComponent() };
    }
    fn verifier(self: *const Components) [4]core.air.components.ForField(Q).Component {
        return .{ self.initial.asVerifierComponent(), self.square.asVerifierComponent(), self.multiply.asVerifierComponent(), self.table.asVerifierComponent() };
    }
};
fn receive(a: std.mem.Allocator, child_bytes: []const u8, proof_bytes: []const u8, mutation: u8) !void {
    if (proof_bytes.len > 16 * 1024 * 1024) return error.DenseProofCap;
    var proof = try Wire.decodeProofBytesBinary(a, proof_bytes);
    var owns = true;
    defer if (owns) proof.deinit(a);
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4) return error.DenseProofShape;
    const fresh_w = D.chain.Witness.init(INPUT_A, INPUT_B);
    var pp = try parts(a, &fresh_w);
    defer for (&pp) |*part| part.deinit();
    var fixed = columns(0, &pp);
    var setup = try Scheme.init(a, CONFIG);
    defer setup.deinit(a);
    setup.setCompactPolynomialStorage(1);
    var scratch = Channel.init();
    try setup.commit(a, &fixed, &scratch);
    var fresh = try setup.roots(a);
    defer fresh.deinit(a);
    if (mutation == 9) {
        // A genuine commitment to a different immutable initial ID program is
        // rejected before child/PCS verification; no producer FIXED authority.
        pp[0].fixed[32 + A.memory.closed_ram.trace.physical(0, 5)] = N.M.fromCanonical(35);
        var substitute = try Scheme.init(a, CONFIG);
        defer substitute.deinit(a);
        substitute.setCompactPolynomialStorage(1);
        var substitute_channel = Channel.init();
        try substitute.commit(a, &fixed, &substitute_channel);
        roots[0] = substitute.trees.items[0].root();
    }
    if (!std.mem.eql(u8, &fresh.items[0], &roots[0])) return error.DenseFixedAuthority;
    var verifier = try Verifier.init(a, CONFIG);
    defer verifier.deinit(a);
    var channel = Channel.init();
    mix(&channel, &fresh_w.public, expectedOutput());
    try verifier.commit(a, roots[0], &FIXED_LOGS, &channel);
    try verifier.commit(a, roots[1], &MAIN_LOGS, &channel);
    const wire = D.chain.Wire.draw(&channel);
    var decoded = try N.decode(a, child_bytes);
    defer decoded.deinit();
    var pending = try N.verify(a, .{ .statement = N.statement(&fresh_w.public, expectedOutput()), .fixed = roots[0], .main = roots[1] }, &decoded.proof);
    defer pending.deinit(a);
    var dd = try data(a, &pending);
    defer for (&dd) |*d| d.deinit();
    const claim = try D.fixture_trace.TraceForLog(.multiply, 9).expectedClaim(.{ .byte = Q.zero(), .wire = wire }, expectedOutput());
    mixReceipt(&channel, pending.digest);
    channel.mixFelts(&.{claim});
    try verifier.commit(a, roots[2], &INTER_LOGS, &channel);
    if (mutation >= 1 and mutation <= 5) {
        const col: usize = switch (mutation) {
            1 => T.offsets(.initial)[2],
            2 => T.offsets(.square)[2] + 16,
            3 => T.offsets(.multiply)[2] + 24,
            4 => T.offsets(.multiply)[2] + 32,
            else => T.offsets(.table)[2] + 8,
        };
        proof.commitment_scheme_proof.sampled_values.items[2][col][0] = proof.commitment_scheme_proof.sampled_values.items[2][col][0].add(Q.one());
    }
    if (mutation == 6) {
        var p = dd[4].point.p;
        p[0] = p[0].add(Q.one());
        dd[4].point = try P.MP.MleEvalPointFor(Q).init(p[0..dd[4].point.n]);
    }
    if (mutation == 7) dd[3].ssa.offset = dd[3].ssa.offset.add(Q.one());
    if (mutation == 8) proof.commitment_scheme_proof.sampled_values.items[1][T.offsets(.initial)[1] + 1][0] = proof.commitment_scheme_proof.sampled_values.items[1][T.offsets(.initial)[1] + 1][0].add(Q.one());
    const cc = Components.init(&dd, wire, claim);
    const vv = cc.verifier();
    owns = false;
    try core.verifier.ForField(Q).verify(H, MC, a, &vv, &channel, &verifier, proof);
}
fn physical(comptime forged: bool) !void {
    const budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(std.testing.allocator, 2 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var w = D.chain.Witness.init(INPUT_A, INPUT_B);
    if (forged) {
        const tmp = D.reference(INPUT_A, INPUT_A);
        var input: [24]u256 = undefined;
        @memcpy(input[0..12], &tmp);
        @memcpy(input[12..], &INPUT_B);
        input[0] += D.spec.B.BN254_P;
        w.square[0] = D.row.Layout(.square).congruentForgeryForTesting(0, &INPUT_A);
        inline for (0..12) |coordinate| w.multiply[coordinate] = D.row.Layout(.multiply).fill(coordinate, &input);
        w.recount();
    }
    var pp = try parts(a, &w);
    defer for (&pp) |*part| part.deinit();
    var fixed = columns(0, &pp);
    var main = columns(1, &pp);
    var scheme = try Scheme.init(a, CONFIG);
    var owns = true;
    defer if (owns) scheme.deinit(a);
    scheme.setCompactPolynomialStorage(1);
    var channel = Channel.init();
    mix(&channel, &w.public, expectedOutput());
    try scheme.commit(a, &fixed, &channel);
    try scheme.commit(a, &main, &channel);
    const wire = D.chain.Wire.draw(&channel);
    const scope = N.Scope{ .statement = N.statement(&w.public, expectedOutput()), .fixed = scheme.trees.items[0].root(), .main = scheme.trees.items[1].root() };
    var child = try N.prove(a, scope, &w);
    defer child.deinit(a);
    const child_bytes = try N.encode(a, &child.result.proof);
    defer a.free(child_bytes);
    var pending = try N.verify(a, scope, &child.result.proof);
    defer pending.deinit(a);
    var dd = try data(a, &pending);
    defer for (&dd) |*d| d.deinit();
    try pp[0].installBinding(&w, &dd[3], 0);
    try pp[1].installBinding(&w, &dd[0], 0);
    try pp[1].installBinding(&w, &dd[4], 1);
    try pp[2].installBinding(&w, &dd[1], 0);
    try pp[2].installBinding(&w, &dd[5], 1);
    try pp[3].installBinding(&w, &dd[2], 0);
    const claim = try pp[2].outputDebt(wire, expectedOutput());
    var inter = columns(2, &pp);
    mixReceipt(&channel, pending.digest);
    channel.mixFelts(&.{claim});
    try scheme.commit(a, &inter, &channel);
    const cc = Components.init(&dd, wire, claim);
    const components = cc.prover();
    owns = false;
    var diagnostic: ?@import("stwo_prover_api").ProveDiagnostic = null;
    var failed: ?core.proof.ForField(Q).ExtendedStarkProof(H) = null;
    var refused = false;
    var result = engine.prove.ForField(Q).proveExWithExecutionDiagnosedRetainingFailure(Backend, H, MC, a, &components, &channel, scheme, false, null, null, null, &diagnostic, &failed) catch |err| blk: {
        if (err != error.ConstraintsNotSatisfied) return err;
        refused = true;
        break :blk failed orelse return error.DenseMissingFailedProof;
    };
    defer result.aux.deinit(a);
    var proof = result.proof;
    defer proof.deinit(a);
    try std.testing.expectEqual(forged, refused);
    const encoded = try Wire.encodeProofBytesBinary(a, proof);
    defer a.free(encoded);
    if (forged) {
        try std.testing.expectError(error.OodsNotMatching, receive(a, child_bytes, encoded, 0));
        if (std.process.getEnvVarOwned(a, "STWO_DENSE_SSA_OUT")) |path| {
            defer a.free(path);
            var dir = try std.fs.cwd().makeOpenPath(path, .{});
            defer dir.close();
            const f = try dir.createFile("temporary-plus-p.unverified.proof.bin", .{ .exclusive = true });
            defer f.close();
            try f.writeAll(encoded);
            const g = try dir.createFile("temporary-plus-p.gkr.bin", .{ .exclusive = true });
            defer g.close();
            try g.writeAll(child_bytes);
        } else |err| if (err != error.EnvironmentVariableNotFound) return err;
        return;
    }
    try receive(a, child_bytes, encoded, 0);
    for (1..9) |m| try std.testing.expect(std.meta.isError(receive(a, child_bytes, encoded, @intCast(m))));
    try std.testing.expectError(error.DenseFixedAuthority, receive(a, child_bytes, encoded, 9));
    if (std.process.getEnvVarOwned(a, "STWO_DENSE_SSA_OUT")) |path| {
        defer a.free(path);
        var dir = try std.fs.cwd().makeOpenPath(path, .{});
        defer dir.close();
        const f = try dir.createFile("chain.proof.bin", .{ .exclusive = true });
        defer f.close();
        try f.writeAll(encoded);
        const g = try dir.createFile("chain.gkr.bin", .{ .exclusive = true });
        defer g.close();
        try g.writeAll(child_bytes);
    } else |err| if (err != error.EnvironmentVariableNotFound) return err;
    std.debug.print("OP_DENSE_SSA_PHYSICAL correctness_only=true arithmetic_logs=8,9 initial_log=5 byte_log=8 inter=16,32,40,16 native_bytes={d} child_bytes={d}\n", .{ encoded.len, child_bytes.len });
}
test "dense SSA chain physical fresh mixed-height source and adversaries" {
    try physical(false);
}
test "dense SSA chain physical coherent temporary plus p rejects canonical writer" {
    try physical(true);
}

fn checkDegree(comptime role: N.Role) !void {
    const Component = C.Component(role);
    var channel = Channel.init();
    const wire = D.chain.Wire.draw(&channel);
    var point: [18]Q = undefined;
    for (&point, 0..) |*v, i| v.* = Q.fromBase(N.M.fromCanonical(@intCast(i + 2)));
    var dd: [6]P.Data = undefined;
    var n: usize = 0;
    defer for (dd[0..n]) |*d| d.deinit();
    for (N.INSTANCES, &dd) |i, *d| {
        const weights = try @import("../../../poseidon2_outer/truth_local_gkr/projection.zig").laneWeightsFor(Q, std.testing.allocator, point[0..i.lane_log]);
        d.* = .{ .allocator = std.testing.allocator, .instance = i, .weights = weights, .point = try P.MP.MleEvalPointFor(Q).init(point[0..i.row_log]), .beta = Q.fromBase(N.M.fromCanonical(13)), .ssa = wire, .eta = Q.fromBase(N.M.fromCanonical(17)), .target = Q.one() };
        n += 1;
    }
    const cc = Components.init(&dd, wire, Q.one());
    const component = switch (role) {
        .initial => cc.initial,
        .square => cc.square,
        .multiply => cc.multiply,
        .table => cc.table,
    };
    const count = comptime (switch (role) {
        .square => D.air.constraints(.square) + 1,
        .multiply => D.air.constraints(.multiply) + 2,
        .initial => 33,
        .table => 0,
    }) + 3 * C.bindingCount(role);
    const Samples = struct {
        step: usize,
        fn value(seed: usize, step: usize) Q {
            var a: [8]N.M = undefined;
            var b: [8]N.M = undefined;
            for (&a, &b, 0..) |*x, *y, i| {
                x.* = N.M.fromCanonical(@intCast(seed * (i + 3) + i + 1));
                y.* = N.M.fromCanonical(@intCast((seed + i + 7) * step));
            }
            return Q.fromM31Array(a).add(Q.fromM31Array(b));
        }
        pub fn get(s: @This(), tree: usize, col: usize, shift: i32) !Q {
            return value(1000 + tree * 3000 + col * 7 + @as(usize, @intCast(shift + 2)), s.step);
        }
        pub fn auxAt(s: @This(), index: usize) !@import("../../../word16_global_execution/services/gkr_local/binding.zig").AuxFor(Q) {
            if (index >= C.bindingCount(role)) return error.DenseSsaShape;
            return .{ .first = value(101 + index, s.step), .second = value(113 + index, s.step), .carry = value(127 + index, s.step), .eq0 = Q.one(), .eq1 = Q.fromBase(N.M.fromCanonical(7)) };
        }
    };
    var residuals: [5][count]Q = undefined;
    for (0..5) |step| {
        var workspace: Component.Workspace(Q) = undefined;
        var sink = A.evaluation.SinkFor(Q){ .values = &residuals[step] };
        try component.emitForWithWorkspace(Q, Samples{ .step = step }, &sink, &workspace);
        try std.testing.expectEqual(count, sink.count);
    }
    for (0..count) |i| {
        const fourth = residuals[0][i].sub(residuals[1][i].mulM31(N.M.fromCanonical(4))).add(residuals[2][i].mulM31(N.M.fromCanonical(6))).sub(residuals[3][i].mulM31(N.M.fromCanonical(4))).add(residuals[4][i]);
        try std.testing.expect(fourth.isZero());
    }
}
test "dense SSA chain complete equations degree three all four roles" {
    inline for (T.ORDER) |role| try checkDegree(role);
}
