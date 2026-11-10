//! Physical G2 transition fixture; CPU/VM service admission remains closed.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const D = A.crypto.bn254_dense;
const G = A.crypto.bn254_g2;
const S = G.spec;
const N = @import("native.zig");
const P = @import("projection.zig");
const C = @import("component.zig");
const T = @import("trace.zig");
const Q = N.Q;
const Backend = @import("stwo_cpu_backend").CpuBackend;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const Protocol = @import("../../word16_global_execution/services/gkr_local/worker_protocol.zig");
const MC = Protocol.MC;
const Channel = Protocol.Channel;
const Scheme = engine.pcs.ForField(Q).CommitmentSchemeProver(Backend, H, MC);
const Verifier = core.pcs.ForField(Q).verifier.CommitmentSchemeVerifier(H, MC);
const Wire = @import("stwo_proof_wire").ForField(Q);
const CONFIG = core.pcs.ForField(Q).PcsConfig{ .pow_bits = 0, .fri_config = .{ .log_last_layer_degree_bound = 0, .log_blowup_factor = 1, .n_queries = 12 } };
fn Qualification(comptime kind: S.Kind) type {
    return struct {
        const V = G.vectors.DATA[if (kind == .doubling) 2 else 3];
        const Part = T.Part(kind);
        const FIXED_LOGS = T.logs(kind, 0);
        const MAIN_LOGS = T.logs(kind, 1);
        const INTER_LOGS = T.logs(kind, 2);
        fn modelFor(comptime index: usize) !G.fixture.Model(kind) {
            const vector = G.vectors.DATA[index];
            const expected_initial = try G.witness.initialValues(kind, vector.input, vector.q);
            return G.fixture.Model(kind).init(try G.witness.Witness(kind).init(vector.input, vector.q), &expected_initial, vector.point, vector.line);
        }
        fn model() !G.fixture.Model(kind) {
            return modelFor(if (kind == .doubling) 2 else 3);
        }
        fn mix(ch: *Channel, public: []const u256) void {
            CONFIG.mixInto(ch);
            ch.mixU32s(&.{ 0x47325353, 1, @intFromEnum(kind), 5, 8, 8, 16, 32, 16 });
            const digest = N.statement(kind, public);
            var words: [8]u32 = undefined;
            for (&words, 0..) |*x, i| x.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
            ch.mixU32s(&words);
        }
        fn mixReceipt(ch: *Channel, digest: core.crypto.poseidon2_m31_sponge.Digest) void {
            var words: [9]u32 = undefined;
            for (&words, 0..) |*x, i| x.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
            ch.mixU32s(&words);
        }
        fn parts(a: std.mem.Allocator, w: *const G.fixture.Model(kind)) ![3]Part {
            var result: [3]Part = undefined;
            var n: usize = 0;
            errdefer for (result[0..n]) |*part| part.deinit();
            inline for (T.ORDER, 0..) |r, i| {
                result[i] = try Part.init(r, a, w);
                n += 1;
            }
            return result;
        }
        fn columns(comptime tree: usize, pp: *const [3]Part) [T.width(kind, tree)]engine.pcs.ColumnEvaluation {
            var out: [T.width(kind, tree)]engine.pcs.ColumnEvaluation = undefined;
            inline for (T.ORDER, 0..) |role, i| {
                const offset = T.offsets(kind, role)[tree];
                const width = switch (tree) {
                    0 => C.fixedWidth(kind, role),
                    1 => C.mainWidth(kind, role),
                    2 => C.interactionWidth(role),
                    else => unreachable,
                };
                pp[i].columns(tree, out[offset..][0..width]);
            }
            return out;
        }
        fn data(a: std.mem.Allocator, pending: *const N.Pending) ![4]P.Data {
            var out: [4]P.Data = undefined;
            var n: usize = 0;
            errdefer for (out[0..n]) |*d| d.deinit();
            for (&out, 0..) |*d, i| {
                d.* = try P.Data.init(a, i, &pending.artifact, pending.beta, pending.ssa, pending.eta);
                n += 1;
            }
            return out;
        }
        const Components = struct {
            frontier: C.Component(kind, .frontier),
            arithmetic: C.Component(kind, .arithmetic),
            table: C.Component(kind, .table),
            fn init(dd: *const [4]P.Data) Components {
                return .{
                    .frontier = .{ .data = .{&dd[3]}, .offsets = T.offsets(kind, .frontier) },
                    .arithmetic = .{ .data = .{ &dd[0], &dd[2] }, .offsets = T.offsets(kind, .arithmetic) },
                    .table = .{ .data = .{&dd[1]}, .offsets = T.offsets(kind, .table) },
                };
            }
            fn prover(self: *const Components) [3]engine.air.component_prover.ForField(Q).ComponentProver {
                return .{ self.frontier.asProverComponent(), self.arithmetic.asProverComponent(), self.table.asProverComponent() };
            }
            fn verifier(self: *const Components) [3]core.air.components.ForField(Q).Component {
                return .{ self.frontier.asVerifierComponent(), self.arithmetic.asVerifierComponent(), self.table.asVerifierComponent() };
            }
        };
        fn receive(a: std.mem.Allocator, child_bytes: []const u8, proof_bytes: []const u8, mutation: u8) !void {
            if (proof_bytes.len > 16 * 1024 * 1024) return error.DenseProofCap;
            var proof = try Wire.decodeProofBytesBinary(a, proof_bytes);
            var owns = true;
            defer if (owns) proof.deinit(a);
            const roots = proof.commitment_scheme_proof.commitments.items;
            if (roots.len != 4) return error.DenseProofShape;
            const fresh_w = if (mutation == 11) try modelFor(if (kind == .doubling) 0 else 1) else try model();
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
            if (mutation == 9 or mutation == 10) {
                // A genuine commitment to a different immutable initial ID program is
                // rejected before child/PCS verification; no producer FIXED authority.
                if (mutation == 9) pp[0].fixed[32 + A.memory.closed_ram.trace.physical(0, 5)] = N.M.fromCanonical(35) else pp[0].fixed[3 * 32 + A.memory.closed_ram.trace.physical(0, 5)] = pp[0].fixed[3 * 32 + A.memory.closed_ram.trace.physical(0, 5)].add(N.M.one());
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
            mix(&channel, &fresh_w.public);
            try verifier.commit(a, roots[0], &FIXED_LOGS, &channel);
            try verifier.commit(a, roots[1], &MAIN_LOGS, &channel);
            var decoded = try N.decode(a, child_bytes);
            defer decoded.deinit();
            var pending = try N.verify(a, .{ .statement = N.statement(kind, &fresh_w.public), .fixed = roots[0], .main = roots[1] }, &decoded.proof);
            defer pending.deinit(a);
            var dd = try data(a, &pending);
            defer for (&dd) |*d| d.deinit();
            mixReceipt(&channel, pending.digest);
            try verifier.commit(a, roots[2], &INTER_LOGS, &channel);
            if (mutation >= 1 and mutation <= 5) {
                const col: usize = switch (mutation) {
                    1 => T.offsets(kind, .frontier)[2],
                    2 => T.offsets(kind, .arithmetic)[2] + 16,
                    3 => T.offsets(kind, .arithmetic)[2] + 24,
                    4 => T.offsets(kind, .table)[2],
                    else => T.offsets(kind, .table)[2] + 8,
                };
                proof.commitment_scheme_proof.sampled_values.items[2][col][0] = proof.commitment_scheme_proof.sampled_values.items[2][col][0].add(Q.one());
            }
            if (mutation == 6) {
                var point = dd[2].point.p;
                point[0] = point[0].add(Q.one());
                dd[2].point = try P.MP.MleEvalPointFor(Q).init(point[0..dd[2].point.n]);
            }
            if (mutation == 7) dd[3].ssa.offset = dd[3].ssa.offset.add(Q.one());
            if (mutation == 8) proof.commitment_scheme_proof.sampled_values.items[1][1][0] = proof.commitment_scheme_proof.sampled_values.items[1][1][0].add(Q.one());
            const cc = Components.init(&dd);
            const vv = cc.verifier();
            owns = false;
            try core.verifier.ForField(Q).verify(H, MC, a, &vv, &channel, &verifier, proof);
        }
        fn physical(comptime forged: bool) !void {
            const budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(std.testing.allocator, 2 << 30);
            defer budget.destroy();
            const a = budget.allocator();
            var w = try model();
            if (forged) {
                const step = if (kind == .doubling) 0 else 4;
                const operands = w.actual.operands(step);
                w.actual.arithmetic[step] = G.witness.Layout(kind).congruentForgeryForTesting(step, &operands);
                const program = comptime S.program(kind);
                w.actual.values[program.operations[step].writer] += S.B.BN254_P;
                inline for (step + 1..comptime S.rows(kind)) |later| {
                    const input = w.actual.operands(later);
                    w.actual.arithmetic[later] = G.witness.Layout(kind).fill(later, &input);
                    w.actual.values[program.operations[later].writer] = G.witness.Layout(kind).output(later, &input);
                }
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
            mix(&channel, &w.public);
            try scheme.commit(a, &fixed, &channel);
            try scheme.commit(a, &main, &channel);
            const scope = N.Scope{ .statement = N.statement(kind, &w.public), .fixed = scheme.trees.items[0].root(), .main = scheme.trees.items[1].root() };
            var child = try N.prove(kind, a, scope, &w);
            defer child.deinit(a);
            const child_bytes = try N.encode(a, &child.result.proof);
            defer a.free(child_bytes);
            var pending = try N.verify(a, scope, &child.result.proof);
            defer pending.deinit(a);
            var dd = try data(a, &pending);
            defer for (&dd) |*d| d.deinit();
            try pp[0].installBinding(&w, &dd[3], 0);
            try pp[1].installBinding(&w, &dd[0], 0);
            try pp[1].installBinding(&w, &dd[2], 1);
            try pp[2].installBinding(&w, &dd[1], 0);
            var inter = columns(2, &pp);
            mixReceipt(&channel, pending.digest);
            try scheme.commit(a, &inter, &channel);
            const cc = Components.init(&dd);
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
                if (std.process.getEnvVarOwned(a, "STWO_G2_OUT")) |path| {
                    defer a.free(path);
                    const class_path = try std.fs.path.join(a, &.{ path, @tagName(kind) });
                    defer a.free(class_path);
                    var dir = try std.fs.cwd().makeOpenPath(class_path, .{});
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
            for (9..12) |m| try std.testing.expectError(error.DenseFixedAuthority, receive(a, child_bytes, encoded, @intCast(m)));

            if (std.process.getEnvVarOwned(a, "STWO_G2_OUT")) |path| {
                defer a.free(path);
                const class_path = try std.fs.path.join(a, &.{ path, @tagName(kind) });
                defer a.free(class_path);
                var dir = try std.fs.cwd().makeOpenPath(class_path, .{});
                defer dir.close();
                const f = try dir.createFile("chain.proof.bin", .{ .exclusive = true });
                defer f.close();
                try f.writeAll(encoded);
                const g = try dir.createFile("chain.gkr.bin", .{ .exclusive = true });
                defer g.close();
                try g.writeAll(child_bytes);
            } else |err| if (err != error.EnvironmentVariableNotFound) return err;
            std.debug.print("OP_G2_PHYSICAL correctness_only=true kind={s} main={d} inter=32 frontier_log=5 arithmetic_log=8 table_log=8 native_bytes={d} child_bytes={d}\n", .{ @tagName(kind), G.witness.Layout(kind).MAIN, encoded.len, child_bytes.len });
        }
    };
}
test "G2 quadratic physical fresh source BYTE SSA closure both transitions" {
    inline for (.{ S.Kind.doubling, S.Kind.addition }) |kind| try Qualification(kind).physical(false);
}
test "G2 quadratic physical coherent noncanonical internal writer rejects" {
    inline for (.{ S.Kind.doubling, S.Kind.addition }) |kind| try Qualification(kind).physical(true);
}

fn checkDegree(comptime kind: S.Kind, comptime role: N.Role) !void {
    const Component = C.Component(kind, role);
    var channel = Channel.init();
    const wire = G.fixture.Wire.draw(&channel);
    var point: [17]Q = undefined;
    for (&point, 0..) |*v, i| v.* = Q.fromBase(N.M.fromCanonical(@intCast(i + 2)));
    var dd: [4]P.Data = undefined;
    var n: usize = 0;
    defer for (dd[0..n]) |*d| d.deinit();
    for (N.INSTANCES, &dd) |i, *d| {
        const weights = try @import("../../poseidon2_outer/truth_local_gkr/projection.zig").laneWeightsFor(Q, std.testing.allocator, point[0..i.lane_log]);
        d.* = .{ .allocator = std.testing.allocator, .instance = i, .weights = weights, .point = try P.MP.MleEvalPointFor(Q).init(point[0..i.row_log]), .beta = Q.fromBase(N.M.fromCanonical(13)), .ssa = wire, .eta = Q.fromBase(N.M.fromCanonical(17)), .target = Q.one() };
        n += 1;
    }
    const cc = Qualification(kind).Components.init(&dd);
    const component = switch (role) {
        .frontier => cc.frontier,
        .arithmetic => cc.arithmetic,
        .table => cc.table,
    };
    const count = comptime G.fixture.constraints(kind, role) + 3 * C.bindingCount(role);
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
        pub fn auxAt(s: @This(), index: usize) !@import("../../word16_global_execution/services/gkr_local/binding.zig").AuxFor(Q) {
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
test "G2 quadratic complete source equations degree three" {
    inline for (.{ S.Kind.doubling, S.Kind.addition }) |kind| inline for (T.ORDER) |role| try checkDegree(kind, role);
}

test "G2 expected frontier is independent of advice and enforces literal constants" {
    inline for (.{ S.Kind.doubling, S.Kind.addition }) |kind| {
        const v = G.vectors.DATA[if (kind == .doubling) 2 else 3];
        const other = G.vectors.DATA[if (kind == .doubling) 0 else 1];
        const expected_initial = try G.witness.initialValues(kind, v.input, v.q);
        var private = try G.witness.Witness(kind).init(v.input, v.q);
        private.initial[0] ^= 1;
        const model = try G.fixture.Model(kind).init(private, &expected_initial, v.point, v.line);
        try std.testing.expectEqual(expected_initial[0], model.public[0]);
        try std.testing.expect(private.initial[0] != model.public[0]);
        var invalid_initial = expected_initial;
        invalid_initial[0] = S.B.BN254_P;
        try std.testing.expectError(error.NonCanonicalExpectedG2Input, G.fixture.Model(kind).init(private, &invalid_initial, v.point, v.line));
        if (kind == .doubling) {
            invalid_initial = expected_initial;
            invalid_initial[6] ^= 1;
            try std.testing.expectError(error.WrongG2SourceConstant, G.fixture.Model(kind).init(private, &invalid_initial, v.point, v.line));
        }
        var invalid_output = v.point;
        invalid_output[0][0] = S.B.BN254_P;
        try std.testing.expectError(error.NonCanonicalExpectedG2Output, G.fixture.Model(kind).init(private, &expected_initial, invalid_output, v.line));
        // Coherently valid arithmetic for another input cannot select its own
        // initial/export frontier: the independently expected local SSA refuses.
        const alternative = try G.fixture.Model(kind).init(try G.witness.Witness(kind).init(other.input, other.q), &expected_initial, v.point, v.line);
        const scope = N.Scope{ .statement = N.statement(kind, &alternative.public), .fixed = @splat(17), .main = @splat(29) };
        try std.testing.expectError(error.UnclosedLocalGkr, N.prove(kind, std.testing.allocator, scope, &alternative));
    }
}
