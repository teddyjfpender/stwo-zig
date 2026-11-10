//! Physical exact conditional subgroup local SSA fixture, not a CPU/VM service admission.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const D = A.crypto.bn254_dense;
const G = A.crypto.bn254_pairing_mac12;
const S = G.source;
const N = @import("native.zig");
const P = @import("projection.zig");
const C = @import("component.zig");
const T = @import("trace.zig");
const Q = N.Q;
const Backend = @import("stwo_cpu_backend").CpuBackend;
const BlakeH = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const Protocol = @import("../../word16_global_execution/services/gkr_local/worker_protocol.zig");
const P2Suite = core.vcs_lifted.poseidon2_profile.Om31V2;
const TOY_CONFIG = core.pcs.ForField(Q).PcsConfig{ .pow_bits = 0, .fri_config = .{ .log_last_layer_degree_bound = 0, .log_blowup_factor = 1, .n_queries = 12 } };
fn Qualification(comptime target: bool) type {
    return QualificationForSuite(target, false);
}
fn QualificationForSuite(comptime target: bool, comptime poseidon: bool) type {
    return struct {
        const H = if (poseidon) P2Suite.MerkleHasher else BlakeH;
        const MC = if (poseidon) P2Suite else Protocol.MC;
        const Channel = if (poseidon) P2Suite.Channel else Protocol.Channel;
        const Wire = @import("stwo_proof_wire").ForHasher(Q, H);
        const Scheme = engine.pcs.ForField(Q).CommitmentSchemeProver(Backend, H, MC);
        const Verifier = core.pcs.ForField(Q).verifier.CommitmentSchemeVerifier(H, MC);
        const Local = if (poseidon) N.Poseidon else N.Blake;
        fn classDirectory() []const u8 {
            return classDirectoryFor(false);
        }
        fn classDirectoryFor(comptime reference: bool) []const u8 {
            if (reference) return if (poseidon) "four-pair-p2-q72-reference" else "four-pair-q72-reference";
            return if (poseidon) "four-pair-p2-q72" else if (target) "four-pair-q72" else "four-pair";
        }

        const CONFIG = if (target) @import("../../poseidon2_outer/op_profile.zig").Profile.op_target_b4_q72_p0_fold4_v1.config() else TOY_CONFIG;
        const V = G.vectors;
        const R = G.residue_vectors;
        fn private() G.original_witness.Private {
            return .{ .seed = R.POSITIVE.seed, .scale = R.POSITIVE.c[0..6].*, .inverse2 = R.POSITIVE.inverse2 };
        }
        fn sourceWitness(a: std.mem.Allocator) !G.original_witness.Witness {
            return G.original_witness.Witness.init(a, V.INPUT, private());
        }
        const Part = T.Part;
        const FIXED_LOGS = T.logs(0);
        const MAIN_LOGS = T.logs(1);
        const INTER_LOGS = T.logs(2);
        fn model(plan: *const G.lowering.Program, actual: *const G.witness.Witness) !G.fixture.Model {
            const independent = try S.initialValues(V.INPUT);
            return G.fixture.Model.init(plan, actual, &independent);
        }
        fn mix(ch: *Channel, public: []const u256) void {
            CONFIG.mixInto(ch);
            ch.mixU32s(&.{ if (poseidon) @as(u32, 0x504d5032) else 0x504d3132, 1, 11, 15, 11, 8, 16, 32, 32, 16 });
            const digest = Local.statement(public);
            var words: [8]u32 = undefined;
            for (&words, 0..) |*x, i| x.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
            ch.mixU32s(&words);
        }
        fn mixReceipt(ch: *Channel, digest: core.crypto.poseidon2_m31_sponge.Digest) void {
            if (poseidon) {
                ch.mixRoot(digest);
                return;
            }
            var words: [9]u32 = undefined;
            for (&words, 0..) |*x, i| x.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
            ch.mixU32s(&words);
        }
        fn parts(a: std.mem.Allocator, w: *G.fixture.Model) ![4]Part {
            var result: [4]Part = undefined;
            var n: usize = 0;
            errdefer for (result[0..n]) |*part| part.deinit();
            inline for (T.ORDER, 0..) |r, i| {
                result[i] = try Part.init(r, a, w);
                n += 1;
            }
            return result;
        }
        fn fixedParts(a: std.mem.Allocator, w: *const G.fixture.Model) ![4]Part {
            var out: [4]Part = undefined;
            var count: usize = 0;
            errdefer for (out[0..count]) |*part| part.deinit();
            inline for (T.ORDER, 0..) |role, i| {
                out[i] = try Part.initFixed(role, a, w);
                count += 1;
            }
            return out;
        }
        fn columns(comptime tree: usize, pp: *const [4]Part) [T.width(tree)]engine.pcs.ColumnEvaluation {
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
            frontier: C.Component(.frontier),
            arithmetic: C.Component(.arithmetic),
            hints: C.Component(.hints),
            table: C.Component(.table),
            fn init(dd: *const [6]P.Data) Components {
                return .{
                    .frontier = .{ .data = .{&dd[5]}, .offsets = T.offsets(.frontier) },
                    .arithmetic = .{ .data = .{ &dd[0], &dd[3] }, .offsets = T.offsets(.arithmetic) },
                    .hints = .{ .data = .{ &dd[1], &dd[4] }, .offsets = T.offsets(.hints) },
                    .table = .{ .data = .{&dd[2]}, .offsets = T.offsets(.table) },
                };
            }
            fn prover(self: *const Components) [4]engine.air.component_prover.ForField(Q).ComponentProver {
                return .{ self.frontier.asProverComponent(), self.arithmetic.asProverComponent(), self.hints.asProverComponent(), self.table.asProverComponent() };
            }
            fn verifier(self: *const Components) [4]core.air.components.ForField(Q).Component {
                return .{ self.frontier.asVerifierComponent(), self.arithmetic.asVerifierComponent(), self.hints.asVerifierComponent(), self.table.asVerifierComponent() };
            }
        };
        fn receive(a: std.mem.Allocator, child_bytes: []const u8, proof_bytes: []const u8, mutation: u8) !void {
            if (proof_bytes.len > 16 * 1024 * 1024) return error.DenseProofCap;
            var proof = try Wire.decodeProofBytesBinary(a, proof_bytes);
            var owns = true;
            defer if (owns) proof.deinit(a);
            const roots = proof.commitment_scheme_proof.commitments.items;
            if (roots.len != 4) return error.DenseProofShape;
            if (!std.meta.eql(proof.commitment_scheme_proof.config, CONFIG) or proof.commitment_scheme_proof.revision_config != null) return error.SubgroupProofProfile;
            var plan = try G.lowering.Program.init(a);
            defer plan.deinit();
            const independent = try S.initialValues(V.INPUT);
            const fresh_w = try G.fixture.Model.initAuthority(&plan, &independent);
            var pp = try fixedParts(a, &fresh_w);
            defer for (&pp) |*part| part.deinit();
            var fixed = columns(0, &pp);
            var setup = try Scheme.init(a, CONFIG);
            defer setup.deinit(a);
            setup.setCompactPolynomialStorage(1);
            var scratch = Channel.init();
            try setup.commit(a, &fixed, &scratch);
            var fresh = try setup.roots(a);
            defer fresh.deinit(a);
            if (mutation >= 9 and mutation <= 13) {
                const indexOf = A.memory.closed_ram.trace.physical;
                const frontrows: usize = 1 << 11;
                const arithrows: usize = 1 << 15;
                const at: usize = switch (mutation) {
                    9 => frontrows + indexOf(0, 11),
                    10 => 3 * frontrows + indexOf(0, 11),
                    11 => (C.fixedWidth(.hints) - 1) * frontrows + indexOf(0, 11),
                    12 => A.crypto.bn254_mac12.source.INPUT_ID * arithrows + indexOf(10, 15),
                    13 => 3 * frontrows + indexOf(S.INITIAL, 11),
                    else => unreachable,
                };
                const part: usize = if (mutation == 11) 2 else if (mutation == 12) 1 else 0;
                pp[part].fixed[at] = pp[part].fixed[at].add(N.M.one());
                var substitute = try Scheme.init(a, CONFIG);
                defer substitute.deinit(a);
                substitute.setCompactPolynomialStorage(1);
                var ch = Channel.init();
                try substitute.commit(a, &fixed, &ch);
                roots[0] = substitute.trees.items[0].root();
            }
            if (!std.mem.eql(u8, &fresh.items[0], &roots[0])) return error.DenseFixedAuthority;
            var verifier = try Verifier.init(a, CONFIG);
            defer verifier.deinit(a);
            var channel = Channel.init();
            mix(&channel, &fresh_w.public);
            try verifier.commit(a, roots[0], &FIXED_LOGS, &channel);
            try verifier.commit(a, roots[1], &MAIN_LOGS, &channel);
            var decoded = try Local.decode(a, child_bytes);
            defer decoded.deinit();
            var pending = try Local.verify(a, .{ .statement = Local.statement(&fresh_w.public), .fixed = roots[0], .main = roots[1] }, &decoded.proof);
            defer pending.deinit(a);
            var dd = try data(a, &pending);
            defer for (&dd) |*d| d.deinit();
            mixReceipt(&channel, pending.digest);
            try verifier.commit(a, roots[2], &INTER_LOGS, &channel);
            if (mutation >= 1 and mutation <= 5) {
                const col: usize = switch (mutation) {
                    1 => T.offsets(.frontier)[2],
                    2 => T.offsets(.arithmetic)[2] + 16,
                    3 => T.offsets(.arithmetic)[2] + 24,
                    4 => T.offsets(.table)[2],
                    else => T.offsets(.table)[2] + 8,
                };
                proof.commitment_scheme_proof.sampled_values.items[2][col][0] = proof.commitment_scheme_proof.sampled_values.items[2][col][0].add(Q.one());
            }
            if (mutation == 6) {
                var point = dd[3].point.p;
                point[0] = point[0].add(Q.one());
                dd[3].point = try P.MP.MleEvalPointFor(Q).init(point[0..dd[3].point.n]);
            }
            if (mutation == 7) dd[5].ssa.offset = dd[5].ssa.offset.add(Q.one());
            if (mutation == 8) proof.commitment_scheme_proof.sampled_values.items[1][1][0] = proof.commitment_scheme_proof.sampled_values.items[1][1][0].add(Q.one());
            const cc = Components.init(&dd);
            const vv = cc.verifier();
            owns = false;
            try core.verifier.ForField(Q).verify(H, MC, a, &vv, &channel, &verifier, proof);
        }
        fn physical(comptime forged: bool) !void {
            return physicalWithEncoder(forged, false);
        }
        fn physicalWithEncoder(comptime forged: bool, comptime reference: bool) !void {
            const budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(std.testing.allocator, 2 << 30);
            defer budget.destroy();
            const a = budget.allocator();
            var pool: engine.work_pool.WorkPool = .{};
            if (target) try pool.initInPlaceWithOptions(.{ .worker_count = 16, .backing_allocator = a });
            defer if (target) pool.deinit();
            var binding: ?engine.work_pool.ScopedPoolBinding = if (target) try engine.work_pool.ScopedPoolBinding.init(&pool) else null;
            defer if (binding) |*b| b.deinit();
            var recording: ?engine.stage_profile.Recorder = if (target) engine.stage_profile.Recorder.initWithOptions(a, "cpu", if (poseidon) "complete_pairing_mac12_p2_workers16" else "complete_pairing_mac12_blake_workers16", .{ .capture_tasks = false, .capture_process_usage = true }) else null;
            defer if (recording) |*r| r.deinit();
            const recorder = if (recording) |*r| r else null;
            var phase = try engine.stage_profile.StageScope.begin(recorder, "pairing.source_witness", "Original pairing source values");
            defer phase.end();
            var actual = try sourceWitness(a);
            defer actual.deinit();
            phase.end();
            phase = try engine.stage_profile.StageScope.begin(recorder, "pairing.lowering", "Immutable source lowering");
            var plan = try G.lowering.Program.init(a);
            defer plan.deinit();
            phase.end();
            phase = try engine.stage_profile.StageScope.begin(recorder, "pairing.normalized_values", "Normalized canonical values");
            var normalized = try G.witness.Witness.init(a, &plan, &actual);
            defer normalized.deinit();
            phase.end();
            phase = try engine.stage_profile.StageScope.begin(recorder, "pairing.diagnostic_check", "Qualification-only normalized value check");
            try std.testing.expect(normalized.satisfied(&plan));
            phase.end();
            phase = try engine.stage_profile.StageScope.begin(recorder, "pairing.columns", "Carry/range rows and column materialization");
            const independent_initial = try S.initialValues(V.INPUT);
            var w = if (reference) try G.fixture.Model.initReferenceForTesting(&plan, &normalized, &independent_initial) else try model(&plan, &normalized);
            var pp = try parts(a, &w);
            defer for (&pp) |*part| part.deinit();
            if (forged) {
                const id = plan.hints[0].writer;
                normalized.values[id] += S.B.BN254_P;
                const alias = normalized.values[id];
                const hint = G.witness.HW.rawForTesting(alias, (S.B.BN254_P - 1) -% alias);
                const hp = A.memory.closed_ram.trace.physical(0, 11);
                for (hint, 0..) |value, col| pp[2].main[col * 2048 + hp] = N.M.fromCanonical(value);
                var changed: usize = 0;
                for (plan.stages, 0..) |stage, index| {
                    var reads = false;
                    for (stage.input) |input_id| reads = reads or input_id == id;
                    if (!reads) continue;
                    var input: A.crypto.bn254_mac12.witness.Inputs = undefined;
                    for (stage.input, &input) |input_id, *value| value.* = normalized.values[input_id];
                    const row = try A.crypto.bn254_mac12.witness.fillRawInputsForTesting(&input, stage.coefficients);
                    try std.testing.expectEqual(@as(u272, normalized.values[stage.writer]), A.crypto.bn254_mac12.witness.read(&row, A.crypto.bn254_mac12.source.OUTPUT, 32));
                    const rp = A.memory.closed_ram.trace.physical(index, 15);
                    for (row, 0..) |value, col| pp[1].main[col * 32768 + rp] = N.M.fromCanonical(value);
                    changed += 1;
                }
                try std.testing.expect(changed > 0);
                try w.recount();
                for (w.table, 0..) |count, row| pp[3].main[A.memory.closed_ram.trace.physical(row, 8)] = N.M.fromCanonical(count);
            }
            var fixed = columns(0, &pp);
            var main = columns(1, &pp);
            var scheme = try Scheme.init(a, CONFIG);
            var owns = true;
            defer if (owns) scheme.deinit(a);
            scheme.setCompactPolynomialStorage(1);
            var channel = Channel.init();
            mix(&channel, &w.public);
            phase.end();
            phase = try engine.stage_profile.StageScope.begin(recorder, "pairing.fixed_commit", "FIXED commitment");
            try scheme.commit(a, &fixed, &channel);
            phase.end();
            phase = try engine.stage_profile.StageScope.begin(recorder, "pairing.main_commit", "MAIN commitment");
            try scheme.commit(a, &main, &channel);
            const scope = Local.Scope{ .statement = Local.statement(&w.public), .fixed = scheme.trees.items[0].root(), .main = scheme.trees.items[1].root() };
            phase.end();
            phase = try engine.stage_profile.StageScope.begin(recorder, "pairing.local_gkr", "Local GKR source/tree/traversal");
            var child = try Local.prove(a, scope, &w);
            defer child.deinit(a);
            phase.end();
            phase = try engine.stage_profile.StageScope.begin(recorder, "pairing.local_encode", "Local child encoding and closure negative control");
            const child_bytes = try Local.encode(a, &child.result.proof);
            defer a.free(child_bytes);
            var pairs: [6][2]Q = undefined;
            var views: [6][]Q = undefined;
            for (&pairs, &views, child.result.proof.output_claims_by_instance) |*pair, *view, original| {
                @memcpy(pair, original);
                view.* = pair;
            }
            pairs[0][0] = pairs[0][0].add(pairs[0][1]);
            pairs[3][0] = pairs[3][0].sub(pairs[3][1]);
            var balanced = child.result.proof;
            balanced.output_claims_by_instance = &views;
            try std.testing.expectError(error.UnclosedLocalGkr, N.close(a, &balanced));
            phase.end();
            phase = try engine.stage_profile.StageScope.begin(recorder, "pairing.local_verify", "Local GKR receipt and native check");
            var pending = try Local.verify(a, scope, &child.result.proof);
            defer pending.deinit(a);
            var dd = try data(a, &pending);
            defer for (&dd) |*d| d.deinit();
            phase.end();
            phase = try engine.stage_profile.StageScope.begin(recorder, "pairing.binding_witness", "Physical terminal binding witness");
            try pp[0].installBinding(&w, &dd[5], 0);
            try pp[1].installBinding(&w, &dd[0], 0);
            try pp[1].installBinding(&w, &dd[3], 1);
            try pp[2].installBinding(&w, &dd[1], 0);
            try pp[2].installBinding(&w, &dd[4], 1);
            try pp[3].installBinding(&w, &dd[2], 0);
            if (target and !reference) {
                phase.end();
                phase = try engine.stage_profile.StageScope.begin(recorder, "pairing.projection_check", "Qualification-only packed/scalar projection equality");
                const slots = [_]struct { part: usize, index: usize }{ .{ .part = 1, .index = 0 }, .{ .part = 2, .index = 0 }, .{ .part = 3, .index = 0 }, .{ .part = 1, .index = 1 }, .{ .part = 2, .index = 1 }, .{ .part = 0, .index = 0 } };
                for (&dd, slots) |*projection, slot| {
                    const reference_values = try P.witnessReferenceForTesting(a, &w, projection);
                    defer a.free(reference_values);
                    const rows = projection.instance.rows();
                    try std.testing.expectEqualSlices(N.M, reference_values, pp[slot.part].inter[slot.index * 16 * rows ..][0 .. 16 * rows]);
                }
                phase.end();
                phase = try engine.stage_profile.StageScope.begin(recorder, "pairing.binding_finish", "Finish terminal binding setup");
            }
            var inter = columns(2, &pp);
            mixReceipt(&channel, pending.digest);
            phase.end();
            phase = try engine.stage_profile.StageScope.begin(recorder, "pairing.inter_commit", "INTER commitment");
            try scheme.commit(a, &inter, &channel);
            const cc = Components.init(&dd);
            const components = cc.prover();
            phase.end();
            phase = try engine.stage_profile.StageScope.begin(recorder, "pairing.native_stark", "Native composition and PCS proof");
            owns = false;
            var diagnostic: ?@import("stwo_prover_api").ProveDiagnostic = null;
            var failed: ?core.proof.ForField(Q).ExtendedStarkProof(H) = null;
            var refused = false;
            var result = engine.prove.ForField(Q).proveExWithExecutionDiagnosedRetainingFailure(Backend, H, MC, a, &components, &channel, scheme, false, recorder, null, null, &diagnostic, &failed) catch |err| blk: {
                if (err != error.ConstraintsNotSatisfied) return err;
                refused = true;
                break :blk failed orelse return error.DenseMissingFailedProof;
            };
            defer result.aux.deinit(a);
            var proof = result.proof;
            defer proof.deinit(a);
            try std.testing.expectEqual(forged, refused);
            phase.end();
            phase = try engine.stage_profile.StageScope.begin(recorder, "pairing.encode", "Encode and persist physical proof");
            const encoded = try Wire.encodeProofBytesBinary(a, proof);
            defer a.free(encoded);
            if (forged) {
                try std.testing.expectError(error.OodsNotMatching, receive(a, child_bytes, encoded, 0));
                if (std.process.getEnvVarOwned(a, "STWO_PAIRING_MAC12_OUT")) |path| {
                    defer a.free(path);
                    const class_path = try std.fs.path.join(a, &.{ path, classDirectoryFor(reference) });
                    defer a.free(class_path);
                    var dir = try std.fs.cwd().makeOpenPath(class_path, .{});
                    defer dir.close();
                    const f = try dir.createFile("coherent-hint-plus-p.unverified.proof.bin", .{ .exclusive = true });
                    defer f.close();
                    try f.writeAll(encoded);
                    const g = try dir.createFile("coherent-hint-plus-p.gkr.bin", .{ .exclusive = true });
                    defer g.close();
                    try g.writeAll(child_bytes);
                } else |err| if (err != error.EnvironmentVariableNotFound) return err;
                return;
            }
            if (std.process.getEnvVarOwned(a, "STWO_PAIRING_MAC12_OUT")) |path| {
                defer a.free(path);
                const class_path = try std.fs.path.join(a, &.{ path, classDirectoryFor(reference) });
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
            phase.end();
            phase = try engine.stage_profile.StageScope.begin(recorder, "pairing.fresh_receiver", "Independent public/source-only receiver");
            try receive(a, child_bytes, encoded, 0);
            phase.end();
            phase = try engine.stage_profile.StageScope.begin(recorder, "pairing.adversaries", "Fresh source and physical negative controls");
            for (1..9) |m| try std.testing.expect(std.meta.isError(receive(a, child_bytes, encoded, @intCast(m))));
            for (9..14) |m| try std.testing.expectError(error.DenseFixedAuthority, receive(a, child_bytes, encoded, @intCast(m)));

            phase.end();
            if (target) {
                const path = std.posix.getenv("STWO_PAIRING_MAC12_OUT") orelse return error.MissingPairingArtifactDirectory;
                var dir = try std.fs.cwd().openDir(path, .{});
                defer dir.close();
                var snapshot = try recorder.?.snapshot(a);
                defer snapshot.deinit(a);
                const json = try std.json.Stringify.valueAlloc(a, snapshot, .{});
                defer a.free(json);
                const stage_path = try std.fs.path.join(a, &.{ classDirectoryFor(reference), "stages.json" });
                defer a.free(stage_path);
                const file = try dir.createFile(stage_path, .{ .exclusive = true });
                defer file.close();
                try file.writeAll(json);
            }
            const usage = budget.snapshot();
            std.debug.print("OP_PAIRING_MAC12_PHYSICAL correctness_only=true arithmetic_log=15 hint_log=11 frontier_log=11 BYTE_log=8 native_bytes={d} child_bytes={d} peak_requested_bytes={d} limit={d}\n", .{ encoded.len, child_bytes.len, usage.peak_live_bytes, usage.limit });
        }
    };
}
test "MAC12 complete four-pair physical fresh source and adversaries" {
    try Qualification(false).physical(false);
}
test "MAC12 complete physical coherent canonical hint alias rejects" {
    try Qualification(false).physical(true);
}

fn checkDegree(comptime role: N.Role) !void {
    const Component = C.Component(role);
    var channel = Protocol.Channel.init();
    const wire = G.fixture.Wire.draw(&channel);
    var point: [24]Q = undefined;
    for (&point, 0..) |*v, i| v.* = Q.fromBase(N.M.fromCanonical(@intCast(i + 2)));
    var dd: [6]P.Data = undefined;
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
        .arithmetic => cc.arithmetic,
        .hints => cc.hints,
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
test "MAC12 complete physical source equations degree three" {
    inline for (T.ORDER) |role| try checkDegree(role);
}

test "MAC12 complete opt-in target q72 caller profile and cross-profile controls" {
    const enabled = std.posix.getenv("STWO_PAIRING_MAC12_TARGET") orelse return error.SkipZigTest;
    if (!std.mem.eql(u8, enabled, "1")) return error.InvalidPairingTargetControl;
    const path = std.posix.getenv("STWO_PAIRING_MAC12_OUT") orelse return error.MissingPairingArtifactDirectory;
    const a = std.testing.allocator;
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    const toy = try dir.readFileAlloc(a, "four-pair/chain.proof.bin", 16 << 20);
    defer a.free(toy);
    const toy_child = try dir.readFileAlloc(a, "four-pair/chain.gkr.bin", 16 << 20);
    defer a.free(toy_child);
    try Qualification(false).receive(a, toy_child, toy, 0);
    try Qualification(true).physical(false);
    try Qualification(true).physicalWithEncoder(false, true);
    const reference_proof = try dir.readFileAlloc(a, "four-pair-q72-reference/chain.proof.bin", 16 << 20);
    defer a.free(reference_proof);
    const reference_child = try dir.readFileAlloc(a, "four-pair-q72-reference/chain.gkr.bin", 16 << 20);
    defer a.free(reference_child);
    const target = try dir.readFileAlloc(a, "four-pair-q72/chain.proof.bin", 16 << 20);
    defer a.free(target);
    const target_child = try dir.readFileAlloc(a, "four-pair-q72/chain.gkr.bin", 16 << 20);
    defer a.free(target_child);
    try std.testing.expectEqualSlices(u8, reference_proof, target);
    try std.testing.expectEqualSlices(u8, reference_child, target_child);
    try Qualification(false).receive(a, toy_child, toy, 0);
    try std.testing.expectError(error.SubgroupProofProfile, Qualification(true).receive(a, toy_child, toy, 0));
    try std.testing.expectError(error.SubgroupProofProfile, Qualification(false).receive(a, target_child, target, 0));
}

test "MAC12 complete opt-in native Poseidon full-root target and cross-suite controls" {
    const enabled = std.posix.getenv("STWO_PAIRING_MAC12_P2") orelse return error.SkipZigTest;
    if (!std.mem.eql(u8, enabled, "1")) return error.InvalidPairingP2Control;
    const path = std.posix.getenv("STWO_PAIRING_MAC12_OUT") orelse return error.MissingPairingArtifactDirectory;
    const a = std.testing.allocator;
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    const blake = try dir.readFileAlloc(a, "four-pair-q72/chain.proof.bin", 16 << 20);
    defer a.free(blake);
    const blake_child = try dir.readFileAlloc(a, "four-pair-q72/chain.gkr.bin", 16 << 20);
    defer a.free(blake_child);
    try Qualification(true).receive(a, blake_child, blake, 0);
    try QualificationForSuite(true, true).physical(false);
    const p2 = try dir.readFileAlloc(a, "four-pair-p2-q72/chain.proof.bin", 16 << 20);
    defer a.free(p2);
    const p2_child = try dir.readFileAlloc(a, "four-pair-p2-q72/chain.gkr.bin", 16 << 20);
    defer a.free(p2_child);

    try std.testing.expect(std.meta.isError(Qualification(true).receive(a, p2_child, p2, 0)));
    try std.testing.expect(std.meta.isError(QualificationForSuite(true, true).receive(a, blake_child, blake, 0)));
    try std.testing.expect(std.meta.isError(N.Blake.decode(a, p2_child)));
    try std.testing.expect(std.meta.isError(N.Poseidon.decode(a, blake_child)));
}
test "MAC12 complete Poseidon scope binds ninth coordinate and canonical full roots" {
    var scope = N.Poseidon.Scope{ .statement = @splat(0), .fixed = @splat(0), .main = @splat(0) };
    var first = try N.Poseidon.begin(scope);
    const beta = first.drawSecureFelt();
    scope.main[32] = 1;
    var ninth = try N.Poseidon.begin(scope);
    try std.testing.expect(!beta.eql(ninth.drawSecureFelt()));
    std.mem.writeInt(u32, scope.main[32..36], 2147483647, .little);
    try std.testing.expect(std.meta.isError(N.Poseidon.begin(scope)));
}
