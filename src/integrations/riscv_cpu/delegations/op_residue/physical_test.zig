//! Conditional residue physical fixture; no complete pairing or VM admission.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const D = A.crypto.bn254_dense;
const G = A.crypto.bn254_residue;
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
fn Qualification(comptime attack: bool) type {
    return struct {
        const V = if (attack) G.vectors.OFF_SUBFIELD else G.vectors.POSITIVE;
        const Part = T.Part;
        const FIXED_LOGS = T.logs(0);
        const MAIN_LOGS = T.logs(1);
        const INTER_LOGS = T.logs(2);
        fn input() G.witness.Input {
            return .{ .z = V.z, .seed = V.seed, .c = V.c[0..6].*, .inverse2 = V.inverse2 };
        }
        fn model(material: *const G.physical_witness.Physical) !G.fixture.Model {
            return G.fixture.Model.init(material, &V.z);
        }
        fn mix(ch: *Channel, public: []const u256) void {
            CONFIG.mixInto(ch);
            ch.mixU32s(&.{ 0x52534445, 1, 6, 10, 9, 5, 8, 16, 32, 32, 32, 16 });
            const digest = N.statement(public);
            var words: [8]u32 = undefined;
            for (&words, 0..) |*x, i| x.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
            ch.mixU32s(&words);
        }
        fn mixReceipt(ch: *Channel, digest: core.crypto.poseidon2_m31_sponge.Digest) void {
            var words: [9]u32 = undefined;
            for (&words, 0..) |*x, i| x.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
            ch.mixU32s(&words);
        }
        fn parts(a: std.mem.Allocator, w: *const G.fixture.Model) ![5]Part {
            var result: [5]Part = undefined;
            var n: usize = 0;
            errdefer for (result[0..n]) |*part| part.deinit();
            inline for (T.ORDER, 0..) |r, i| {
                result[i] = try Part.init(r, a, w);
                n += 1;
            }
            return result;
        }
        fn columns(comptime tree: usize, pp: *const [5]Part) [T.width(tree)]engine.pcs.ColumnEvaluation {
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
        fn data(a: std.mem.Allocator, pending: *const N.Pending) ![8]P.Data {
            var out: [8]P.Data = undefined;
            var n: usize = 0;
            errdefer for (out[0..n]) |*d| d.deinit();
            for (&out, 0..) |*d, i| {
                d.* = try P.Data.init(a, i, &pending.artifact, pending.beta, pending.ssa, pending.eta);
                n += 1;
            }
            return out;
        }
        const Components = struct {
            frontier: C.Component(.frontier),
            square: C.Component(.square),
            multiply: C.Component(.multiply),
            hint: C.Component(.hint),
            table: C.Component(.table),
            fn init(dd: *const [8]P.Data) Components {
                return .{
                    .frontier = .{ .data = .{&dd[7]}, .offsets = T.offsets(.frontier) },
                    .square = .{ .data = .{ &dd[0], &dd[4] }, .offsets = T.offsets(.square) },
                    .multiply = .{ .data = .{ &dd[1], &dd[5] }, .offsets = T.offsets(.multiply) },
                    .hint = .{ .data = .{ &dd[2], &dd[6] }, .offsets = T.offsets(.hint) },
                    .table = .{ .data = .{&dd[3]}, .offsets = T.offsets(.table) },
                };
            }
            fn prover(self: *const Components) [5]engine.air.component_prover.ForField(Q).ComponentProver {
                return .{ self.frontier.asProverComponent(), self.square.asProverComponent(), self.multiply.asProverComponent(), self.hint.asProverComponent(), self.table.asProverComponent() };
            }
            fn verifier(self: *const Components) [5]core.air.components.ForField(Q).Component {
                return .{ self.frontier.asVerifierComponent(), self.square.asVerifierComponent(), self.multiply.asVerifierComponent(), self.hint.asVerifierComponent(), self.table.asVerifierComponent() };
            }
        };
        fn receive(a: std.mem.Allocator, child_bytes: []const u8, proof_bytes: []const u8, mutation: u8) !void {
            if (proof_bytes.len > 16 * 1024 * 1024) return error.DenseProofCap;
            var proof = try Wire.decodeProofBytesBinary(a, proof_bytes);
            var owns = true;
            defer if (owns) proof.deinit(a);
            const roots = proof.commitment_scheme_proof.commitments.items;
            if (roots.len != 4) return error.DenseProofShape;
            var independent = try G.witness.Witness.init(a, input());
            defer independent.deinit();
            var independent_physical = try G.physical_witness.Physical.init(a, &independent);
            defer independent_physical.deinit();
            const fresh_w = try model(&independent_physical);
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
                const pos = A.memory.closed_ram.trace.physical;
                if (mutation == 9) pp[0].fixed[3 * 64 + pos(S.ZERO, 6)] = N.M.one() else pp[2].fixed[G.fixture.goalColumn() * 512 + pos(0, 9)] = N.M.zero();
                var substitute = try Scheme.init(a, CONFIG);
                defer substitute.deinit(a);
                substitute.setCompactPolynomialStorage(1);
                var sub_channel = Channel.init();
                try substitute.commit(a, &fixed, &sub_channel);
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
            var pending = try N.verify(a, .{ .statement = N.statement(&fresh_w.public), .fixed = roots[0], .main = roots[1] }, &decoded.proof);
            defer pending.deinit(a);
            var dd = try data(a, &pending);
            defer for (&dd) |*d| d.deinit();
            mixReceipt(&channel, pending.digest);
            try verifier.commit(a, roots[2], &INTER_LOGS, &channel);
            if (mutation >= 1 and mutation <= 5) {
                const col: usize = switch (mutation) {
                    1 => T.offsets(.frontier)[2],
                    2 => T.offsets(.square)[2] + 16,
                    3 => T.offsets(.square)[2] + 24,
                    4 => T.offsets(.table)[2],
                    else => T.offsets(.table)[2] + 8,
                };
                proof.commitment_scheme_proof.sampled_values.items[2][col][0] = proof.commitment_scheme_proof.sampled_values.items[2][col][0].add(Q.one());
            }
            if (mutation == 6) {
                var point = dd[5].point.p;
                point[0] = point[0].add(Q.one());
                dd[5].point = try P.MP.MleEvalPointFor(Q).init(point[0..dd[5].point.n]);
            }
            if (mutation == 7) dd[7].ssa.offset = dd[7].ssa.offset.add(Q.one());
            if (mutation == 8) proof.commitment_scheme_proof.sampled_values.items[1][1][0] = proof.commitment_scheme_proof.sampled_values.items[1][1][0].add(Q.one());
            const cc = Components.init(&dd);
            const vv = cc.verifier();
            owns = false;
            try core.verifier.ForField(Q).verify(H, MC, a, &vv, &channel, &verifier, proof);
        }
        fn physical() !void {
            const budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(std.testing.allocator, 2 << 30);
            defer budget.destroy();
            const a = budget.allocator();
            var actual = try G.witness.Witness.init(a, input());
            defer actual.deinit();
            if (attack) actual.injectOffSubfieldForTesting(&V.c);
            var merged = try G.physical_witness.Physical.init(a, &actual);
            defer merged.deinit();
            var w = try model(&merged);
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
            const scope = N.Scope{ .statement = N.statement(&w.public), .fixed = scheme.trees.items[0].root(), .main = scheme.trees.items[1].root() };
            var child = if (attack) try N.proveLyingForTesting(a, scope, &w) else try N.prove(a, scope, &w);
            defer child.deinit(a);
            const child_bytes = try N.encode(a, &child.result.proof);
            defer a.free(child_bytes);
            var pairs: [8][2]Q = undefined;
            var views: [8][]Q = undefined;
            for (&pairs, &views, child.result.proof.output_claims_by_instance) |*pair, *view, original| {
                @memcpy(pair, original);
                view.* = pair;
            }
            pairs[0][0] = pairs[0][0].add(pairs[0][1]);
            pairs[4][0] = pairs[4][0].sub(pairs[4][1]);
            var balanced = child.result.proof;
            balanced.output_claims_by_instance = &views;
            try std.testing.expectError(error.UnclosedLocalGkr, N.close(a, &balanced));
            var pending = try N.verify(a, scope, &child.result.proof);
            defer pending.deinit(a);
            var dd = try data(a, &pending);
            defer for (&dd) |*d| d.deinit();
            try pp[0].installBinding(&w, &dd[7], 0);
            try pp[1].installBinding(&w, &dd[0], 0);
            try pp[1].installBinding(&w, &dd[4], 1);
            try pp[2].installBinding(&w, &dd[1], 0);
            if (attack) {
                try std.testing.expectError(error.UnboundLocalGkrInput, P.witness(a, &w, &dd[5]));
                const unbound = try P.witnessUnboundForTesting(a, &w, &dd[5]);
                defer a.free(unbound);
                @memcpy(pp[2].inter[16 * 512 ..][0 .. 16 * 512], unbound);
            } else try pp[2].installBinding(&w, &dd[5], 1);
            try pp[3].installBinding(&w, &dd[2], 0);
            try pp[3].installBinding(&w, &dd[6], 1);
            try pp[4].installBinding(&w, &dd[3], 0);
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
            try std.testing.expectEqual(attack, refused);
            const encoded = try Wire.encodeProofBytesBinary(a, proof);
            defer a.free(encoded);
            if (attack) {
                try std.testing.expectError(error.OodsNotMatching, receive(a, child_bytes, encoded, 0));
                if (std.process.getEnvVarOwned(a, "STWO_RESIDUE_OUT")) |path| {
                    defer a.free(path);
                    const class_path = try std.fs.path.join(a, &.{ path, "certificate" });
                    defer a.free(class_path);
                    var dir = try std.fs.cwd().makeOpenPath(class_path, .{});
                    defer dir.close();
                    const f = try dir.createFile("off-subfield.unverified.proof.bin", .{ .exclusive = true });
                    defer f.close();
                    try f.writeAll(encoded);
                    const g = try dir.createFile("off-subfield.gkr.bin", .{ .exclusive = true });
                    defer g.close();
                    try g.writeAll(child_bytes);
                } else |err| if (err != error.EnvironmentVariableNotFound) return err;
                return;
            }
            try receive(a, child_bytes, encoded, 0);
            for (1..9) |m| try std.testing.expect(std.meta.isError(receive(a, child_bytes, encoded, @intCast(m))));
            for (9..11) |m| try std.testing.expectError(error.DenseFixedAuthority, receive(a, child_bytes, encoded, @intCast(m)));

            if (std.process.getEnvVarOwned(a, "STWO_RESIDUE_OUT")) |path| {
                defer a.free(path);
                const class_path = try std.fs.path.join(a, &.{ path, "certificate" });
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
            const usage = budget.snapshot();
            std.debug.print("OP_RESIDUE_PHYSICAL correctness_only=true native_bytes={d} child_bytes={d} peak_requested_bytes={d} limit={d}\n", .{ encoded.len, child_bytes.len, usage.peak_live_bytes, usage.limit });
        }
    };
}
test "BN254 residue physical positive certificate fresh source and adversaries" {
    try Qualification(false).physical();
}
test "BN254 residue physical off-subfield inverse-scale attack fails source binding" {
    try Qualification(true).physical();
}

fn checkDegree(comptime role: N.Role) !void {
    const Component = C.Component(role);
    var channel = Channel.init();
    const wire = G.fixture.Wire.draw(&channel);
    var point: [19]Q = undefined;
    for (&point, 0..) |*v, i| v.* = Q.fromBase(N.M.fromCanonical(@intCast(i + 2)));
    var dd: [8]P.Data = undefined;
    var n: usize = 0;
    defer for (dd[0..n]) |*d| d.deinit();
    for (N.INSTANCES, &dd) |i, *d| {
        const weights = try @import("../../poseidon2_outer/truth_local_gkr/projection.zig").laneWeightsFor(Q, std.testing.allocator, point[0..i.lane_log]);
        d.* = .{ .allocator = std.testing.allocator, .instance = i, .weights = weights, .point = try P.MP.MleEvalPointFor(Q).init(point[0..i.row_log]), .beta = Q.fromBase(N.M.fromCanonical(13)), .ssa = wire, .eta = Q.fromBase(N.M.fromCanonical(17)), .target = Q.one() };
        n += 1;
    }
    const cc = Qualification(false).Components.init(&dd);
    const component = switch (role) {
        .frontier => cc.frontier,
        .square => cc.square,
        .multiply => cc.multiply,
        .hint => cc.hint,
        .table => cc.table,
    };
    const count = comptime G.fixture.constraints(role) + 3 * C.bindingCount(role);
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
test "BN254 residue complete equations degree three" {
    inline for (T.ORDER) |role| try checkDegree(role);
}
