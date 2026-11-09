//! Two independent row geometries in one proof. BYTE counts are committed in
//! their own log8 table; the receiving source never accepts producer geometry.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const D = A.crypto.bn254_dense;
const N = @import("native.zig");
const C = @import("component.zig");
const P = @import("projection.zig");
const Q = N.Q;
const M = N.M;
const Backend = @import("stwo_cpu_backend").CpuBackend;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const Protocol = @import("../../../word16_global_execution/services/gkr_local/worker_protocol.zig");
const MC = Protocol.MC;
const Channel = Protocol.Channel;
const Scheme = engine.pcs.ForField(Q).CommitmentSchemeProver(Backend, H, MC);
const Verifier = core.pcs.ForField(Q).verifier.CommitmentSchemeVerifier(H, MC);
const Wire = @import("stwo_proof_wire").ForField(Q);
const CONFIG = core.pcs.ForField(Q).PcsConfig{ .pow_bits = 0, .fri_config = .{ .log_last_layer_degree_bound = 0, .log_blowup_factor = 1, .n_queries = 12 } };
fn mixReceipt(channel: *Channel, digest: core.crypto.poseidon2_m31_sponge.Digest) void {
    var words: [9]u32 = undefined;
    for (&words, 0..) |*x, i| x.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
}
fn columns(data: []const M, log: u32, out: []engine.pcs.ColumnEvaluation) void {
    const rows = @as(usize, 1) << @intCast(log);
    for (out, 0..) |*v, i| v.* = .{ .log_size = log, .values = data[i * rows ..][0..rows] };
}
fn Qualification(comptime kind: D.spec.Kind, comptime log: u32) type {
    return struct {
        const R = D.row.Layout(kind);
        const Trace = D.fixture_trace.TraceForLog(kind, log);
        const Arith = C.Component(kind, .arithmetic);
        const Table = C.Component(kind, .table);
        const FIXED_LOGS = ([_]u32{log} ** D.air.FIXED) ++ [_]u32{8};
        const MAIN_LOGS = ([_]u32{log} ** R.MAIN) ++ [_]u32{8};
        const INTER_LOGS = ([_]u32{log} ** 24) ++ ([_]u32{8} ** 16);
        const INPUT = blk: {
            var a: [D.spec.inputs(kind)]u256 = undefined;
            for (&a, 0..) |*x, i| x.* = if (i % 3 == 0) std.math.maxInt(u256) else if (i % 3 == 1) D.spec.B.BN254_P - 1 else 19 * i + 3;
            break :blk a;
        };
        fn expected() [12]u256 {
            return D.reference(INPUT[0..12].*, if (kind == .square) INPUT[0..12].* else INPUT[12..24].*);
        }
        fn mix(channel: *Channel, input: *const [D.spec.inputs(kind)]u256, out: [12]u256) void {
            CONFIG.mixInto(channel);
            channel.mixU32s(&.{ 0x444c474b, 2, @intFromEnum(kind), log, 8, 12, R.MAIN, 24, 1, 16, 355 });
            var words: [8]u32 = undefined;
            const id = N.statement(kind, log, input, out);
            for (&words, 0..) |*x, i| x.* = std.mem.readInt(u32, id[4 * i ..][0..4], .little);
            channel.mixU32s(&words);
        }
        fn scope(input: *const [D.spec.inputs(kind)]u256, out: [12]u256, fixed: [32]u8, main: [32]u8) N.Scope {
            return .{ .statement = N.statement(kind, log, input, out), .fixed = fixed, .main = main, .arith_log = log };
        }
        fn receive(a: std.mem.Allocator, child_bytes: []const u8, proof_bytes: []const u8, input: *const [D.spec.inputs(kind)]u256, out: [12]u256, mutation: u8) !void {
            if (proof_bytes.len > 16 * 1024 * 1024) return error.DenseProofCap;
            var proof = try Wire.decodeProofBytesBinary(a, proof_bytes);
            var owns = true;
            defer if (owns) proof.deinit(a);
            const roots = proof.commitment_scheme_proof.commitments.items;
            if (roots.len != 4) return error.DenseProofShape;
            const fixed = try Trace.fixedAlloc(a);
            defer a.free(fixed);
            const byte_fixed = try P.tableFixed(a);
            defer a.free(byte_fixed);
            var fixed_columns: [D.air.FIXED + 1]engine.pcs.ColumnEvaluation = undefined;
            columns(fixed, log, fixed_columns[0..D.air.FIXED]);
            columns(byte_fixed, 8, fixed_columns[D.air.FIXED..]);
            var setup = try Scheme.init(a, CONFIG);
            defer setup.deinit(a);
            setup.setCompactPolynomialStorage(1);
            var scratch = Channel.init();
            try setup.commit(a, &fixed_columns, &scratch);
            var fresh = try setup.roots(a);
            defer fresh.deinit(a);
            if (!std.mem.eql(u8, &fresh.items[0], &roots[0])) return error.DenseFixedAuthority;
            var verifier = try Verifier.init(a, CONFIG);
            defer verifier.deinit(a);
            var channel = Channel.init();
            mix(&channel, input, out);
            try verifier.commit(a, roots[0], &FIXED_LOGS, &channel);
            try verifier.commit(a, roots[1], &MAIN_LOGS, &channel);
            const wire = A.crypto.curves.equations.WireFor(Q).draw(&channel);
            var encoded = try N.decode(a, log, child_bytes);
            defer encoded.deinit();
            var pending = try N.verify(a, scope(input, out, roots[0], roots[1]), &encoded.proof);
            defer pending.deinit(a);
            var ad = try P.Data.init(a, log, 0, &pending.artifact, pending.beta, pending.eta);
            defer ad.deinit();
            var td = try P.Data.init(a, log, 1, &pending.artifact, pending.beta, pending.eta);
            defer td.deinit();
            const claim = try Trace.expectedClaim(.{ .byte = pending.beta, .wire = wire }, out);
            mixReceipt(&channel, pending.digest);
            channel.mixFelts(&.{claim});
            try verifier.commit(a, roots[2], &INTER_LOGS, &channel);
            if (mutation >= 1 and mutation <= 5) {
                const col: usize = switch (mutation) {
                    1 => 0,
                    2 => 8,
                    3 => 16,
                    4 => 24,
                    else => 32,
                };
                proof.commitment_scheme_proof.sampled_values.items[2][col][0] = proof.commitment_scheme_proof.sampled_values.items[2][col][0].add(Q.one());
            }
            if (mutation == 6) {
                var point = ad.point.p;
                point[0] = point[0].add(Q.one());
                ad.point = try P.MP.MleEvalPointFor(Q).init(point[0..log]);
            }
            if (mutation == 7) td.beta = td.beta.add(Q.one());
            const arith = Arith{ .input = input, .data = &ad, .wire = wire, .claim = claim, .log_size = log };
            const table = Table{ .input = input, .data = &td, .wire = wire, .claim = Q.zero(), .log_size = 8, .offsets = .{ D.air.FIXED, R.MAIN, 24 } };
            const components = [_]core.air.components.ForField(Q).Component{ arith.asVerifierComponent(), table.asVerifierComponent() };
            owns = false;
            try core.verifier.ForField(Q).verify(H, MC, a, &components, &channel, &verifier, proof);
        }
        pub fn run() !void {
            const budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(std.testing.allocator, 2 << 30);
            defer budget.destroy();
            const a = budget.allocator();
            var trace = try Trace.initMainOnly(a, &INPUT);
            defer trace.deinit();
            try std.testing.expectEqual(@as(usize, 0), trace.inter.len);
            const table_main = try P.splitProvider(kind, log, a, &trace);
            defer a.free(table_main);
            const table_fixed = try P.tableFixed(a);
            defer a.free(table_fixed);
            var fixed: [D.air.FIXED + 1]engine.pcs.ColumnEvaluation = undefined;
            var main: [R.MAIN + 1]engine.pcs.ColumnEvaluation = undefined;
            columns(trace.fixed, log, fixed[0..D.air.FIXED]);
            columns(table_fixed, 8, fixed[D.air.FIXED..]);
            columns(trace.main, log, main[0..R.MAIN]);
            columns(table_main, 8, main[R.MAIN..]);
            var scheme = try Scheme.init(a, CONFIG);
            var owns = true;
            defer if (owns) scheme.deinit(a);
            scheme.setCompactPolynomialStorage(1);
            var channel = Channel.init();
            mix(&channel, &INPUT, expected());
            try scheme.commit(a, &fixed, &channel);
            try scheme.commit(a, &main, &channel);
            const wire = A.crypto.curves.equations.WireFor(Q).draw(&channel);
            const scoped = scope(&INPUT, expected(), scheme.trees.items[0].root(), scheme.trees.items[1].root());
            var child = try N.prove(kind, log, a, scoped, &trace, table_main);
            defer child.deinit(a);
            const child_bytes = try N.encode(a, log, &child.result.proof);
            defer a.free(child_bytes);
            var pending = try N.verify(a, scoped, &child.result.proof);
            defer pending.deinit(a);
            try std.testing.expectEqual(child.digest, pending.digest);
            var ad = try P.Data.init(a, log, 0, &pending.artifact, pending.beta, pending.eta);
            defer ad.deinit();
            var td = try P.Data.init(a, log, 1, &pending.artifact, pending.beta, pending.eta);
            defer td.deinit();
            const ab = try P.witness(kind, log, a, &trace, table_main, &ad);
            defer a.free(ab);
            const tb = try P.witness(kind, log, a, &trace, table_main, &td);
            defer a.free(tb);
            const global = try P.globalWitness(kind, log, a, &trace, wire, expected());
            defer a.free(global.columns);
            var inter: [40]engine.pcs.ColumnEvaluation = undefined;
            columns(ab, log, inter[0..16]);
            columns(global.columns, log, inter[16..24]);
            columns(tb, 8, inter[24..]);
            mixReceipt(&channel, pending.digest);
            channel.mixFelts(&.{global.claim});
            try scheme.commit(a, &inter, &channel);
            const arith = Arith{ .input = &INPUT, .data = &ad, .wire = wire, .claim = global.claim, .log_size = log };
            const table = Table{ .input = &INPUT, .data = &td, .wire = wire, .claim = Q.zero(), .log_size = 8, .offsets = .{ D.air.FIXED, R.MAIN, 24 } };
            const components = [_]engine.air.component_prover.ForField(Q).ComponentProver{ arith.asProverComponent(), table.asProverComponent() };
            owns = false;
            var proof = try engine.prove.ForField(Q).prove(Backend, H, MC, a, &components, &channel, scheme);
            defer proof.deinit(a);
            const bytes = try Wire.encodeProofBytesBinary(a, proof);
            defer a.free(bytes);
            if (std.process.getEnvVarOwned(a, "STWO_DENSE_LOCAL_OUT")) |path| {
                defer a.free(path);
                var dir = try std.fs.cwd().makeOpenPath(path, .{});
                defer dir.close();
                const name = try std.fmt.allocPrint(a, "{s}-k{d}", .{ @tagName(kind), log });
                defer a.free(name);
                const pn = try std.fmt.allocPrint(a, "{s}.proof.bin", .{name});
                defer a.free(pn);
                const gn = try std.fmt.allocPrint(a, "{s}.gkr.bin", .{name});
                defer a.free(gn);
                const f = try dir.createFile(pn, .{ .exclusive = true });
                defer f.close();
                try f.writeAll(bytes);
                const g = try dir.createFile(gn, .{ .exclusive = true });
                defer g.close();
                try g.writeAll(child_bytes);
            } else |err| if (err != error.EnvironmentVariableNotFound) return err;
            try receive(a, child_bytes, bytes, &INPUT, expected(), 0);
            for (1..8) |m| try std.testing.expect(std.meta.isError(receive(a, child_bytes, bytes, &INPUT, expected(), @intCast(m))));
            var wrong = INPUT;
            wrong[0] ^= 1;
            try std.testing.expect(std.meta.isError(receive(a, child_bytes, bytes, &wrong, expected(), 0)));
            const changed = try a.dupe(u8, child_bytes);
            defer a.free(changed);
            changed[changed.len - 1] ^= 1;
            try std.testing.expect(std.meta.isError(receive(a, changed, bytes, &INPUT, expected(), 0)));
            var bad_shape = N.decode(a, if (log == 8) 9 else 8, child_bytes);
            if (bad_shape) |*value| {
                value.deinit();
                return error.DenseProducerGeometryAccepted;
            } else |err| try std.testing.expect(err == error.LocalGkrReceiptShape);
            std.debug.print("OP_DENSE_SPLIT_LOCAL_PHYSICAL correctness_only=true kind={s} arithmetic_log={d} table_log=8 main={d}/1 inter=24/16 native_bytes={d} child_bytes={d}\n", .{ @tagName(kind), log, R.MAIN, bytes.len, child_bytes.len });
        }
    };
}
test "direct dense multiply equal-log split BYTE GKR physical fresh receiver" {
    try Qualification(.multiply, 8).run();
}
test "direct dense multiply lifted log9 arithmetic log8 BYTE GKR physical fresh receiver" {
    try Qualification(.multiply, 9).run();
}
test "direct dense square lifted log9 arithmetic log8 BYTE GKR physical fresh receiver" {
    try Qualification(.square, 9).run();
}
fn checkDegree(comptime kind: D.spec.Kind, comptime role: N.Role) !void {
    const role_log: u32 = if (role == .arithmetic) 9 else 8;
    const R = D.row.Layout(kind);
    const Component = C.Component(kind, role);
    const ii = try N.instances(9);
    const instance = ii[if (role == .arithmetic) 0 else 1];
    var point: [9]Q = undefined;
    for (&point, 0..) |*v, i| v.* = Q.fromBase(M.fromCanonical(@intCast(i + 2)));
    const weights = try @import("../../../poseidon2_outer/truth_local_gkr/projection.zig").laneWeightsFor(Q, std.testing.allocator, if (role == .arithmetic) point[0..9] else &.{});
    defer std.testing.allocator.free(weights);
    const data = P.Data{ .allocator = std.testing.allocator, .instance = instance, .weights = weights, .point = try P.MP.MleEvalPointFor(Q).init(point[0..role_log]), .beta = Q.fromBase(M.fromCanonical(13)), .eta = Q.fromBase(M.fromCanonical(17)), .target = Q.one() };
    var input: [D.spec.inputs(kind)]u256 = @splat(19);
    var channel = Channel.init();
    const wire = A.crypto.curves.equations.WireFor(Q).draw(&channel);
    const component = Component{ .input = &input, .data = &data, .wire = wire, .claim = Q.one(), .log_size = role_log };
    const count = comptime if (role == .arithmetic) D.air.constraints(kind) + 5 else 3;
    const Samples = struct {
        step: usize,
        fn value(seed: usize, step: usize) Q {
            var a: [8]M = undefined;
            var b: [8]M = undefined;
            for (&a, &b, 0..) |*x, *y, i| {
                x.* = M.fromCanonical(@intCast(seed * (i + 3) + i + 1));
                y.* = M.fromCanonical(@intCast((seed + i + 7) * step));
            }
            return Q.fromM31Array(a).add(Q.fromM31Array(b));
        }
        pub fn get(s: @This(), tree: usize, column: usize, shift: i32) !Q {
            return value(1000 + tree * 3000 + column * 7 + @as(usize, @intCast(shift + 2)), s.step);
        }
        pub fn auxAt(s: @This(), index: usize) !@import("../../../word16_global_execution/services/gkr_local/binding.zig").AuxFor(Q) {
            if (index != 0) return error.DenseProjectionShape;
            return .{ .first = value(101, s.step), .second = value(113, s.step), .carry = value(127, s.step), .eq0 = Q.one(), .eq1 = Q.fromBase(M.fromCanonical(7)) };
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
        const fourth = residuals[0][i].sub(residuals[1][i].mulM31(M.fromCanonical(4))).add(residuals[2][i].mulM31(M.fromCanonical(6))).sub(residuals[3][i].mulM31(M.fromCanonical(4))).add(residuals[4][i]);
        try std.testing.expect(fourth.isZero());
    }
    _ = R;
}
test "direct dense split GKR complete equations degree three both roles and classes" {
    inline for (.{ D.spec.Kind.multiply, D.spec.Kind.square }) |kind| inline for (.{ N.Role.arithmetic, N.Role.table }) |role| try checkDegree(kind, role);
}

fn chainRowsValid(w: *const D.chain.Witness) !bool {
    var residuals: [D.air.constraints(.multiply)]Q = undefined;
    for (0..32) |r| {
        const v = w.view(.initial, r);
        var sink = A.evaluation.SinkFor(Q){ .values = &residuals };
        D.chain.emitInitial(Q, &v, &sink);
        for (residuals[0..sink.count]) |x| if (!x.isZero()) return false;
    }
    inline for (.{ D.chain.Role.square, D.chain.Role.multiply }) |role| for (0..12) |r| {
        const v = w.view(role, r);
        const kind: D.spec.Kind = if (role == .square) .square else .multiply;
        var sink = A.evaluation.SinkFor(Q){ .values = &residuals };
        D.air.emitInherited(kind, Q, &v, &sink);
        try std.testing.expectEqual(D.air.constraints(kind), sink.count);
        for (residuals[0..sink.count]) |x| if (!x.isZero()) return false;
    };
    return true;
}
test "dense SSA chain immutable writers inherited reads and coherent noncanonical temporary" {
    const Chain = D.chain;
    var a: [12]u256 = undefined;
    var b: [12]u256 = undefined;
    for (&a, &b, 0..) |*x, *y, i| {
        x.* = @as(u256, 0x123456789abcdef) * (i + 1);
        y.* = @as(u256, 0x987654321) * (i + 19);
    }
    a[0] = std.math.maxInt(u256); // initial authority permits raw u256 operands
    var w = Chain.Witness.init(a, b);
    var channel = core.channel.poseidon2_m31.Om31ChannelV2.init();
    channel.mixU32s(&.{ 0x44535341, 1 });
    const beta = channel.drawSecureFelt();
    const ssa = Chain.Wire.draw(&channel);
    try std.testing.expect(try chainRowsValid(&w));
    try std.testing.expect((try w.ssaSum(ssa)).isZero());
    try std.testing.expect((try w.byteSum(beta)).isZero());
    const tmp = D.reference(a, a);
    try std.testing.expectEqual(D.reference(tmp, b), w.output);
    // Full source-owned writer/fanout ledger: unique IDs and acyclic reads.
    var writes: [36]u32 = @splat(0);
    var reads: [36]u32 = @splat(0);
    inline for (.{ Chain.Role.initial, Chain.Role.square, Chain.Role.multiply }) |role| {
        for (0..if (role == .initial) @as(usize, 32) else 12) |r| for (0..Chain.lanes(role)) |lane| {
            if (Chain.edge(role, r, lane)) |edge| {
                try std.testing.expect(edge.id <= Chain.MAX_ID);
                if (edge.weight > 0) {
                    try std.testing.expectEqual(@as(u32, 0), writes[edge.id]);
                    writes[edge.id] = @intCast(edge.weight);
                } else reads[edge.id] += @intCast(-edge.weight);
            }
        };
    }
    try std.testing.expectEqual(writes, reads);
    var mass: u32 = 0;
    for (writes) |x| mass += x;
    try std.testing.expectEqual(@as(u32, Chain.SSA_POSITIVE_MASS), mass);
    // Altering a single Mul read passes no public-equality gate: SSA must reject.
    var forged = w;
    forged.multiply[0][D.row.Layout(.multiply).INPUT] ^= 1;
    try std.testing.expect(!(try forged.ssaSum(ssa)).isZero());
    // Missing initial writer is caught independently by source public ROM and SSA.
    forged = w;
    forged.initial[0][0] = 0;
    try std.testing.expect(!try chainRowsValid(&forged));
    try std.testing.expect(!(try forged.ssaSum(ssa)).isZero());
    // Wrong ID and wrong fanout cannot be disguised as a change of a free
    // witness column: they disagree with the immutable ROM rational ledger.
    const initial_view = w.view(.initial, 0);
    const original = Chain.fraction(.initial, Q, &initial_view, ssa, 0);
    var initial_bytes: [32]Q = undefined;
    for (&initial_bytes, 0..) |*x, i| x.* = initial_view.main(1 + i);
    const wrong_id = Chain.denominator(Q, Q.fromBase(M.fromCanonical(35)), initial_bytes, ssa);
    const changed_id_debt = original[0].mul(try wrong_id.inv()).sub(original[0].mul(try original[1].inv()));
    try std.testing.expect(!changed_id_debt.isZero());
    try std.testing.expect(!(try original[1].inv()).isZero()); // a +/-1 fanout error
    // Coherent tmp+p: all input reads follow the forged canonical-looking byte
    // vector, all integer carries and BYTE/SSA rational sums remain valid, and
    // final modular output is unchanged. Only canonical-write authority rejects.
    forged = w;
    forged.square[0] = D.row.Layout(.square).congruentForgeryForTesting(0, &a);
    var m_input: [24]u256 = undefined;
    @memcpy(m_input[0..12], &tmp);
    @memcpy(m_input[12..], &b);
    m_input[0] += D.spec.B.BN254_P;
    inline for (0..12) |coordinate| forged.multiply[coordinate] = D.row.Layout(.multiply).fill(coordinate, &m_input);
    forged.recount();
    try std.testing.expect((try forged.ssaSum(ssa)).isZero());
    try std.testing.expect((try forged.byteSum(beta)).isZero());
    try std.testing.expect(D.row.Layout(.square).carriedValid(0, &forged.square[0]));
    try std.testing.expect(D.row.Layout(.square).rangeValid(&forged.square[0]));
    try std.testing.expect(!try chainRowsValid(&forged));
    inline for (0..12) |coordinate| try std.testing.expectEqual(w.output[coordinate], D.row.Layout(.multiply).output(coordinate, &m_input));
}

test "dense SSA chain six source GKR instances separate relation closure" {
    const Join = @import("../local_ssa/native.zig");
    const a = std.testing.allocator;
    const w = D.chain.Witness.init(@splat(17), @splat(29));
    const scope = Join.Scope{ .statement = Join.statement(&w.public, w.output), .fixed = @splat(71), .main = @splat(83) };
    var child = try Join.prove(a, scope, &w);
    defer child.deinit(a);
    const encoded = try Join.encode(a, &child.result.proof);
    defer a.free(encoded);
    var decoded = try Join.decode(a, encoded);
    defer decoded.deinit();
    var pending = try Join.verify(a, scope, &decoded.proof);
    defer pending.deinit(a);
    try std.testing.expectEqual(child.digest, pending.digest);
    try std.testing.expectEqual(child.beta, pending.beta);
    try std.testing.expectEqual(child.ssa, pending.ssa);
    try std.testing.expectEqual(@as(usize, 18), pending.artifact.ood_point.len);
    var facts: usize = 0;
    for (Join.INSTANCES) |i| facts += i.facts();
    try std.testing.expectEqual(@as(usize, 413984), facts);
    // A balanced transfer between BYTE and SSA would fool a single aggregate
    // closure. Each typed relation must close separately.
    var pairs: [6][2]Q = undefined;
    var pair_views: [6][]Q = undefined;
    for (&pairs, &pair_views, decoded.proof.output_claims_by_instance) |*pair, *view, original| {
        @memcpy(pair, original);
        view.* = pair;
    }
    pairs[0][0] = pairs[0][0].add(pairs[0][1]);
    pairs[3][0] = pairs[3][0].sub(pairs[3][1]);
    var forged_proof = decoded.proof;
    forged_proof.output_claims_by_instance = &pair_views;
    try std.testing.expectError(error.UnclosedLocalGkr, Join.close(a, &forged_proof));
    var missing_writer = w;
    missing_writer.initial[0][0] = 0;
    try std.testing.expectError(error.UnclosedLocalGkr, Join.prove(a, scope, &missing_writer));
    // Shape is fully source-derived, including mixed row and lane dimensions.
    for (Join.INSTANCES, pending.artifact.n_variables_by_instance) |i, v| try std.testing.expectEqual(try i.variables(), v);
    // Scope changes the independently drawn BYTE and SSA transcript, so the old
    // child cannot be transplanted to a different public input/MAIN/ROM frame.
    var wrong = scope;
    wrong.main[0] ^= 1;
    if (Join.verify(a, wrong, &decoded.proof)) |*accepted_value| {
        var accepted = accepted_value.*;
        accepted.deinit(a);
        return error.AcceptedWrongSsaScope;
    } else |_| {}
}
